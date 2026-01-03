package adapters

import (
	"context"
	"log/slog"
	"time"

	"credo/internal/auth/types"
	"credo/pkg/platform/circuit"
)

// ClientResolver resolves client metadata and tenant ownership.
type ClientResolver interface {
	ResolveClient(ctx context.Context, clientID string) (*types.ResolvedClient, *types.ResolvedTenant, error)
}

// ResilientClientResolver wraps a ClientResolver with circuit breaker protection.
// When the circuit opens (after consecutive failures), it returns cached
// client data if available, preventing cascade failures.
type ResilientClientResolver struct {
	delegate ClientResolver
	cb       *circuit.Breaker
	cache    *clientCache
	logger   *slog.Logger
}

// ResilientClientResolverOption configures the resilient resolver.
type ResilientClientResolverOption func(*resolverConfig)

type resolverConfig struct {
	failureThreshold int
	successThreshold int
	cacheTTL         time.Duration
}

// WithFailureThreshold sets the number of consecutive failures to open the circuit.
func WithFailureThreshold(n int) ResilientClientResolverOption {
	return func(c *resolverConfig) {
		c.failureThreshold = n
	}
}

// WithSuccessThreshold sets the number of consecutive successes to close the circuit.
func WithSuccessThreshold(n int) ResilientClientResolverOption {
	return func(c *resolverConfig) {
		c.successThreshold = n
	}
}

// WithCacheTTL sets the cache TTL for client data.
func WithCacheTTL(ttl time.Duration) ResilientClientResolverOption {
	return func(c *resolverConfig) {
		c.cacheTTL = ttl
	}
}

// NewResilientClientResolver creates a circuit-breaker-protected client resolver.
func NewResilientClientResolver(
	delegate ClientResolver,
	logger *slog.Logger,
	opts ...ResilientClientResolverOption,
) *ResilientClientResolver {
	cfg := &resolverConfig{
		failureThreshold: 5,
		successThreshold: 3,
		cacheTTL:         5 * time.Minute,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	var cbOpts []circuit.Option
	if cfg.failureThreshold > 0 {
		cbOpts = append(cbOpts, circuit.WithFailureThreshold(cfg.failureThreshold))
	}
	if cfg.successThreshold > 0 {
		cbOpts = append(cbOpts, circuit.WithSuccessThreshold(cfg.successThreshold))
	}

	return &ResilientClientResolver{
		delegate: delegate,
		cb:       circuit.New("client_resolver", cbOpts...),
		cache:    newClientCache(cfg.cacheTTL),
		logger:   logger,
	}
}

// ResolveClient resolves a client with circuit breaker protection.
// On success: caches the result and records success.
// On failure: records failure, returns cached data if circuit is open.
func (r *ResilientClientResolver) ResolveClient(ctx context.Context, clientID string) (*types.ResolvedClient, *types.ResolvedTenant, error) {
	// If circuit is open, try cache first
	if r.cb.IsOpen() {
		if client, tenant, ok := r.cache.Get(clientID); ok {
			r.logger.WarnContext(ctx, "circuit open, using cached client",
				"client_id", clientID,
				"circuit", r.cb.Name(),
			)
			return client, tenant, nil
		}
		// No cache hit and circuit open - still try delegate (half-open behavior)
	}

	// Try delegate
	client, tenant, err := r.delegate.ResolveClient(ctx, clientID)
	if err != nil {
		useFallback, change := r.cb.RecordFailure()
		if change.Opened {
			r.logger.ErrorContext(ctx, "circuit breaker opened",
				"circuit", r.cb.Name(),
				"error", err,
			)
		}

		// If circuit is open and we have cached data, use it
		if useFallback {
			if cachedClient, cachedTenant, ok := r.cache.Get(clientID); ok {
				r.logger.WarnContext(ctx, "using cached client after failure",
					"client_id", clientID,
					"circuit", r.cb.Name(),
				)
				return cachedClient, cachedTenant, nil
			}
		}

		return nil, nil, err
	}

	// Success: record and cache
	_, change := r.cb.RecordSuccess()
	if change.Closed {
		r.logger.InfoContext(ctx, "circuit breaker closed",
			"circuit", r.cb.Name(),
		)
	}

	r.cache.Set(clientID, client, tenant)
	return client, tenant, nil
}

// Ensure ResilientClientResolver implements the interface expected by auth service.
var _ interface {
	ResolveClient(ctx context.Context, clientID string) (*types.ResolvedClient, *types.ResolvedTenant, error)
} = (*ResilientClientResolver)(nil)
