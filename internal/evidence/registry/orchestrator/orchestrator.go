package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"credo/internal/evidence/registry/providers"
)

// retryBudget tracks the global retry count across all providers in a lookup.
// Uses atomic operations for thread-safe decrementing in parallel strategies.
type retryBudget struct {
	remaining int32
}

// newRetryBudget creates a new retry budget with the given limit.
func newRetryBudget(limit int) *retryBudget {
	return &retryBudget{remaining: int32(limit)}
}

// tryConsume attempts to consume one retry from the budget.
// Returns true if a retry is available, false if the budget is exhausted.
func (b *retryBudget) tryConsume() bool {
	for {
		current := atomic.LoadInt32(&b.remaining)
		if current <= 0 {
			return false
		}
		if atomic.CompareAndSwapInt32(&b.remaining, current, current-1) {
			return true
		}
	}
}

// LookupStrategy defines how providers are selected and queried during evidence gathering.
// The choice of strategy affects reliability, latency, and resource usage.
type LookupStrategy string

const (
	// StrategyPrimary uses only the primary provider
	StrategyPrimary LookupStrategy = "primary"

	// StrategyFallback tries primary, then falls back to secondary on failure
	StrategyFallback LookupStrategy = "fallback"

	// StrategyParallel queries all providers in parallel and merges results
	StrategyParallel LookupStrategy = "parallel"

	// StrategyVoting queries multiple providers and uses majority vote
	StrategyVoting LookupStrategy = "voting"
)

// CorrelationRule defines how to reconcile and merge evidence from multiple sources.
// Rules are applied after parallel lookups to resolve conflicts between providers.
type CorrelationRule interface {
	// Merge combines evidence from multiple providers into a single authoritative record.
	// Returns the merged evidence or an error if merging is not possible.
	Merge(evidence []*providers.Evidence) (*providers.Evidence, error)

	// Applicable returns true if this rule can process the given combination of evidence types.
	// The orchestrator will try rules in order until one is applicable and succeeds.
	Applicable(types []providers.ProviderType) bool
}

// ProviderChain defines a sequence of providers with fallback logic.
// When using StrategyFallback, the orchestrator will try Primary first,
// then each Secondary in order until one succeeds.
type ProviderChain struct {
	Primary   string   // Primary provider ID
	Secondary []string // Fallback provider IDs, tried in order
	Timeout   time.Duration
}

// BackoffConfig configures retry backoff for retryable errors
type BackoffConfig struct {
	InitialDelay      time.Duration // Initial delay before first retry (default: 100ms)
	MaxDelay          time.Duration // Maximum delay between retries (default: 2s)
	MaxRetries        int           // Maximum number of retries per provider (default: 3)
	Multiplier        float64       // Multiplier for exponential backoff (default: 2.0)
	GlobalRetryBudget int           // Maximum total retries across all providers (default: 10)
}

// OrchestratorConfig configures the evidence orchestrator
type OrchestratorConfig struct {
	Registry        *providers.ProviderRegistry
	DefaultStrategy LookupStrategy
	DefaultTimeout  time.Duration

	// Chains defines provider preferences by evidence type
	Chains map[providers.ProviderType]ProviderChain

	// Rules defines how to correlate multi-source evidence
	Rules []CorrelationRule

	// Backoff configures retry behavior for retryable errors
	Backoff BackoffConfig
}

// Orchestrator coordinates multi-source evidence gathering from registry providers.
//
// It supports multiple lookup strategies (primary, fallback, parallel, voting) and
// handles provider failures with configurable retry backoff. When multiple providers
// return results, correlation rules can merge conflicting evidence into a single record.
type Orchestrator struct {
	registry *providers.ProviderRegistry
	chains   map[providers.ProviderType]ProviderChain
	rules    []CorrelationRule
	strategy LookupStrategy
	timeout  time.Duration
	backoff  BackoffConfig
}

// New creates a new evidence orchestrator
func New(cfg OrchestratorConfig) *Orchestrator {
	if cfg.DefaultTimeout == 0 {
		cfg.DefaultTimeout = 5 * time.Second
	}
	if cfg.DefaultStrategy == "" {
		cfg.DefaultStrategy = StrategyFallback
	}

	// Apply backoff defaults
	if cfg.Backoff.InitialDelay == 0 {
		cfg.Backoff.InitialDelay = 100 * time.Millisecond
	}
	if cfg.Backoff.MaxDelay == 0 {
		cfg.Backoff.MaxDelay = 2 * time.Second
	}
	if cfg.Backoff.MaxRetries == 0 {
		cfg.Backoff.MaxRetries = 3
	}
	if cfg.Backoff.Multiplier == 0 {
		cfg.Backoff.Multiplier = 2.0
	}
	if cfg.Backoff.GlobalRetryBudget == 0 {
		cfg.Backoff.GlobalRetryBudget = 10
	}

	return &Orchestrator{
		registry: cfg.Registry,
		chains:   cfg.Chains,
		rules:    cfg.Rules,
		strategy: cfg.DefaultStrategy,
		timeout:  cfg.DefaultTimeout,
		backoff:  cfg.Backoff,
	}
}

// LookupRequest describes what evidence to gather
type LookupRequest struct {
	Types    []providers.ProviderType // What types of evidence to gather
	Filters  map[string]string        // Input filters (national_id, etc.)
	Strategy LookupStrategy           // Override default strategy
	Timeout  time.Duration            // Override default timeout
}

// LookupResult contains all gathered evidence
type LookupResult struct {
	Evidence []*providers.Evidence
	Errors   map[string]error // Provider ID -> error
}

// Lookup gathers evidence according to the request using the specified or default strategy.
//
// The method applies a context timeout (from request or default) before dispatching to
// the appropriate strategy implementation. All strategies return partial results in
// LookupResult.Errors when some providers fail, allowing callers to decide whether
// partial evidence is acceptable.
func (o *Orchestrator) Lookup(ctx context.Context, req LookupRequest) (*LookupResult, error) {
	// Apply default timeout if not specified
	timeout := req.Timeout
	if timeout == 0 {
		timeout = o.timeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Apply default strategy if not specified
	strategy := req.Strategy
	if strategy == "" {
		strategy = o.strategy
	}

	// Gather evidence based on strategy
	switch strategy {
	case StrategyPrimary:
		return o.lookupPrimary(ctx, req)
	case StrategyFallback:
		return o.lookupFallback(ctx, req)
	case StrategyParallel:
		return o.lookupParallel(ctx, req)
	case StrategyVoting:
		return o.lookupVoting(ctx, req)
	default:
		return nil, fmt.Errorf("unknown strategy: %s", strategy)
	}
}

// lookupPrimary uses only the primary provider for each type
func (o *Orchestrator) lookupPrimary(ctx context.Context, req LookupRequest) (*LookupResult, error) {
	result := &LookupResult{
		Evidence: make([]*providers.Evidence, 0, len(req.Types)),
		Errors:   make(map[string]error),
	}

	for _, typ := range req.Types {
		chain, err := o.getChainForType(typ)
		if err != nil {
			result.Errors["no-provider"] = err
			continue
		}

		provider, ok := o.registry.Get(chain.Primary)
		if !ok {
			result.Errors[chain.Primary] = providers.ErrProviderNotFound
			continue
		}

		evidence, err := provider.Lookup(ctx, req.Filters)
		if err != nil {
			result.Errors[provider.ID()] = err
			continue
		}

		result.Evidence = append(result.Evidence, evidence)
	}

	if len(result.Evidence) == 0 && len(result.Errors) > 0 {
		return result, providers.ErrAllProvidersFailed
	}

	return result, nil
}

// lookupFallback tries primary, then falls back to secondary on failure.
// Uses a global retry budget to prevent cascade failures across providers.
func (o *Orchestrator) lookupFallback(ctx context.Context, req LookupRequest) (*LookupResult, error) {
	result := &LookupResult{
		Evidence: make([]*providers.Evidence, 0, len(req.Types)),
		Errors:   make(map[string]error),
	}

	// Create a shared retry budget for this lookup
	budget := newRetryBudget(o.backoff.GlobalRetryBudget)

	for _, typ := range req.Types {
		chain, err := o.getChainForType(typ)
		if err != nil {
			result.Errors["no-provider"] = err
			continue
		}

		if evidence := o.tryChainWithFallback(ctx, chain, req.Filters, result.Errors, budget); evidence != nil {
			result.Evidence = append(result.Evidence, evidence)
		}
	}

	if len(result.Evidence) == 0 && len(result.Errors) > 0 {
		return result, providers.ErrAllProvidersFailed
	}

	return result, nil
}

// getChainForType returns the provider chain for a given type.
// If no chain is configured, it creates one from the first available provider.
func (o *Orchestrator) getChainForType(typ providers.ProviderType) (ProviderChain, error) {
	if chain, ok := o.chains[typ]; ok {
		return chain, nil
	}

	provs := o.registry.ListByType(typ)
	if len(provs) == 0 {
		return ProviderChain{}, providers.ErrNoProvidersAvailable
	}

	return ProviderChain{Primary: provs[0].ID()}, nil
}

// tryChainWithFallback attempts the primary provider, then falls back to secondaries.
// Records errors in the provided map and returns evidence if any provider succeeds.
// The budget parameter limits total retries across all providers in this lookup.
func (o *Orchestrator) tryChainWithFallback(ctx context.Context, chain ProviderChain, filters map[string]string, errors map[string]error, budget *retryBudget) *providers.Evidence {
	// Try primary first with backoff for retryable errors
	evidence, err := o.tryProviderWithBackoff(ctx, chain.Primary, filters, budget)
	if err == nil {
		return evidence
	}
	errors[chain.Primary] = err

	// Try fallbacks if primary failed
	for _, secondaryID := range chain.Secondary {
		evidence, err := o.tryProviderWithBackoff(ctx, secondaryID, filters, budget)
		if err == nil {
			return evidence
		}
		errors[secondaryID] = err
	}

	return nil
}

// lookupParallel queries all providers of each requested type concurrently.
//
// For each provider type, it spawns goroutines to query all registered providers simultaneously.
// Results are collected with mutex protection. After all goroutines complete, correlation rules
// are applied to merge multiple evidence records if applicable. This strategy prioritizes
// completeness over latency by waiting for all providers to respond (or timeout).
func (o *Orchestrator) lookupParallel(ctx context.Context, req LookupRequest) (*LookupResult, error) {
	result := &LookupResult{
		Evidence: make([]*providers.Evidence, 0),
		Errors:   make(map[string]error),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, typ := range req.Types {
		provs := o.registry.ListByType(typ)

		for _, prov := range provs {
			wg.Add(1)
			go func(p providers.Provider) {
				defer wg.Done()

				evidence, err := p.Lookup(ctx, req.Filters)

				mu.Lock()
				defer mu.Unlock()

				if err != nil {
					result.Errors[p.ID()] = err
				} else {
					result.Evidence = append(result.Evidence, evidence)
				}
			}(prov)
		}
	}

	wg.Wait()

	// Apply correlation rules to merge evidence from multiple sources
	o.applyCorrelationRules(result)

	if len(result.Evidence) == 0 && len(result.Errors) > 0 {
		return result, providers.ErrAllProvidersFailed
	}

	return result, nil
}

// applyCorrelationRules merges evidence from multiple providers using configured rules.
// If multiple evidence records exist and an applicable rule succeeds, the evidence is
// replaced with the merged result. This separates correlation logic from concurrency concerns.
func (o *Orchestrator) applyCorrelationRules(result *LookupResult) {
	if len(o.rules) == 0 || len(result.Evidence) < 2 {
		return
	}

	types := make([]providers.ProviderType, 0, len(result.Evidence))
	for _, e := range result.Evidence {
		types = append(types, e.ProviderType)
	}

	for _, rule := range o.rules {
		if rule.Applicable(types) {
			if merged, err := rule.Merge(result.Evidence); err == nil {
				result.Evidence = []*providers.Evidence{merged}
				return
			}
		}
	}
}

// lookupVoting queries multiple providers and selects evidence by highest confidence per type.
//
// First performs a parallel lookup, then for each provider type, keeps only the evidence
// with the highest confidence score. This is a simplified voting strategy that currently
// does not implement true majority voting - it assumes higher confidence indicates more
// authoritative data.
func (o *Orchestrator) lookupVoting(ctx context.Context, req LookupRequest) (*LookupResult, error) {
	// First do parallel lookup
	result, err := o.lookupParallel(ctx, req)
	if err != nil {
		return result, err
	}

	// TODO: Implement voting logic based on confidence scores
	// For now, just return the highest confidence evidence per type

	typeMap := make(map[providers.ProviderType]*providers.Evidence)
	for _, e := range result.Evidence {
		existing, ok := typeMap[e.ProviderType]
		if !ok || e.Confidence > existing.Confidence {
			typeMap[e.ProviderType] = e
		}
	}

	result.Evidence = make([]*providers.Evidence, 0, len(typeMap))
	for _, e := range typeMap {
		result.Evidence = append(result.Evidence, e)
	}

	return result, nil
}

// tryProviderWithBackoff attempts to get evidence with exponential backoff for retryable errors.
//
// The method retries up to MaxRetries times for errors marked as retryable (timeouts, rate limits,
// provider outages). Non-retryable errors (bad data, not found, auth failures) fail immediately.
// Delay between retries grows exponentially: InitialDelay * (Multiplier ^ attempt), capped at MaxDelay.
// Respects context cancellation between retry attempts.
//
// The budget parameter enforces a global retry limit across all providers. If the budget is
// exhausted, retries stop even if per-provider MaxRetries hasn't been reached.
func (o *Orchestrator) tryProviderWithBackoff(ctx context.Context, providerID string, filters map[string]string, budget *retryBudget) (*providers.Evidence, error) {
	provider, ok := o.registry.Get(providerID)
	if !ok {
		return nil, providers.ErrProviderNotFound
	}

	var lastErr error
	delay := o.backoff.InitialDelay

	for attempt := 0; attempt <= o.backoff.MaxRetries; attempt++ {
		// Wait before retry (skip on first attempt)
		if attempt > 0 {
			// Check global retry budget before retrying
			if budget != nil && !budget.tryConsume() {
				return nil, lastErr
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}

			// Calculate next delay with exponential backoff
			delay = time.Duration(float64(delay) * o.backoff.Multiplier)
			if delay > o.backoff.MaxDelay {
				delay = o.backoff.MaxDelay
			}
		}

		evidence, err := provider.Lookup(ctx, filters)
		if err == nil {
			return evidence, nil
		}

		lastErr = err

		// Only retry if error is retryable
		if !providers.IsRetryable(err) {
			return nil, err
		}
	}

	return nil, lastErr
}

// HealthCheck checks the health of all registered providers concurrently.
//
// Each provider's Health method is called in parallel. The returned map contains provider IDs
// as keys; nil values indicate healthy providers, non-nil values contain the health check error.
// This is useful for monitoring dashboards and readiness probes.
func (o *Orchestrator) HealthCheck(ctx context.Context) map[string]error {
	provs := o.registry.All()
	results := make(map[string]error, len(provs))

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, prov := range provs {
		wg.Add(1)
		go func(p providers.Provider) {
			defer wg.Done()
			err := p.Health(ctx)

			mu.Lock()
			results[p.ID()] = err
			mu.Unlock()
		}(prov)
	}

	wg.Wait()
	return results
}
