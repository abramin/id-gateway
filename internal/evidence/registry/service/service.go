package service

import (
	"context"
	"errors"
	"log/slog"

	"credo/internal/evidence/registry/models"
	"credo/internal/evidence/registry/orchestrator"
	"credo/internal/evidence/registry/ports"
	"credo/internal/evidence/registry/providers"
	"credo/internal/evidence/registry/store"
	"credo/internal/evidence/registry/tracer"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
)

// Service coordinates registry lookups with caching and optional PII minimisation.
//
// The service implements a cache-through pattern where lookups first check the cache,
// then fall back to the orchestrator for cache misses. Results are cached on successful lookup.
//
// When regulated mode is enabled, citizen records are minimized to remove PII (name, DOB, address)
// before being returned or cached, retaining only the Valid flag for GDPR compliance.
//
// Consent is checked atomically within service methods to prevent TOCTOU races between
// consent verification and the actual lookup operation.
//
// Distributed tracing is supported via an optional Tracer. When configured, the service
// emits spans for registry.check (parent), registry.citizen, and registry.sanctions operations
// with cache hit/miss annotations.
type Service struct {
	orchestrator *orchestrator.Orchestrator
	cache        CacheStore
	consentPort  ports.ConsentPort
	regulated    bool
	logger       *slog.Logger
	tracer       tracer.Tracer
}

// CacheStore defines the interface for registry caching operations.
// Implementations should return store.ErrNotFound for cache misses to distinguish
// from actual errors. The service treats any non-ErrNotFound error as a failure.
//
// The regulated parameter indicates whether the record was stored in minimized form.
// Cache implementations should return ErrNotFound if the stored regulated mode
// doesn't match the requested mode, preventing stale PII from being served.
//
// Save methods accept the lookup key separately from the record to prevent cache
// key collisions when records are minimized (e.g., regulated mode blanks NationalID).
type CacheStore interface {
	FindCitizen(ctx context.Context, nationalID id.NationalID, regulated bool) (*models.CitizenRecord, error)
	SaveCitizen(ctx context.Context, key id.NationalID, record *models.CitizenRecord, regulated bool) error
	FindSanction(ctx context.Context, nationalID id.NationalID) (*models.SanctionsRecord, error)
	SaveSanction(ctx context.Context, key id.NationalID, record *models.SanctionsRecord) error
}

// Option configures the Service.
type Option func(*Service)

// WithLogger sets the logger for the service.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Service) {
		s.logger = logger
	}
}

// WithTracer sets the tracer for distributed tracing.
// When set, the service emits spans for registry operations with cache annotations.
func WithTracer(t tracer.Tracer) Option {
	return func(s *Service) {
		s.tracer = t
	}
}

// New creates a new registry service using the orchestrator pattern.
// The consentPort enables atomic consent verification within service methods.
func New(orch *orchestrator.Orchestrator, cache CacheStore, consentPort ports.ConsentPort, regulated bool, opts ...Option) *Service {
	s := &Service{
		orchestrator: orch,
		cache:        cache,
		consentPort:  consentPort,
		regulated:    regulated,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Check performs atomic citizen and sanctions lookups with transaction-like semantics.
//
// The method operates in four phases:
//  1. Consent check: Verifies consent atomically before any lookup
//  2. Cache check: Retrieves any cached records to avoid redundant lookups
//  3. Fetch missing: Queries the orchestrator only for records not in cache
//  4. Atomic commit: Caches results only if BOTH lookups succeeded
//
// This ensures consistency: if one lookup fails, no partial state is cached,
// preventing scenarios where retrying would see stale data for one record type.
// If regulated mode is enabled, citizen PII is stripped before caching.
//
// When a tracer is configured, this method emits a parent span (registry.check) with
// child spans for citizen and sanctions lookups, annotated with cache hit/miss attributes.
func (s *Service) Check(ctx context.Context, userID id.UserID, nationalID id.NationalID) (result *models.RegistryResult, err error) {
	// Start parent span if tracer is configured
	ctx, span := s.startSpan(ctx, tracer.SpanRegistryCheck,
		tracer.String(tracer.AttrNationalID, tracer.HashNationalID(nationalID.String())),
		tracer.Bool(tracer.AttrRegulatedMode, s.regulated),
	)
	defer func() { s.endSpan(span, err) }()

	// Phase 1: Atomic consent check - must succeed before any lookup
	if err = s.requireConsent(ctx, userID); err != nil {
		return nil, err
	}

	// Phase 2: Check cache with tracing
	cached, err := s.checkCacheWithTracing(ctx, nationalID, span)
	if err != nil {
		return nil, err
	}
	if cached.AllCached() {
		return &models.RegistryResult{Citizen: cached.citizen, Sanction: cached.sanction}, nil
	}

	// Phase 3: Fetch missing from orchestrator with tracing
	fetchResult, err := s.fetchMissingWithTracing(ctx, nationalID, cached)
	if err != nil {
		return nil, err
	}

	// Convert evidence to domain models
	fetchedCitizen, fetchedSanction, err := s.convertEvidence(fetchResult)
	if err != nil {
		return nil, err
	}

	// Merge cached and fetched records
	citizen := cached.citizen
	sanction := cached.sanction
	if !cached.citizenCached {
		citizen = fetchedCitizen
	}
	if !cached.sanctionsCached {
		sanction = fetchedSanction
	}

	// Validate we got all required evidence
	if citizen == nil || sanction == nil {
		err = s.translateOrchestratorError(providers.ErrAllProvidersFailed, fetchResult)
		return nil, err
	}

	// Phase 4: Atomic cache commit - only cache if both lookups succeeded
	s.cacheNewlyFetched(ctx, nationalID, citizen, sanction, cached)

	return &models.RegistryResult{Citizen: citizen, Sanction: sanction}, nil
}

// cacheCheckResult holds the results of a cache lookup for both citizen and sanctions.
// This struct reduces the cognitive load of tracking multiple return values.
type cacheCheckResult struct {
	citizen         *models.CitizenRecord
	sanction        *models.SanctionsRecord
	citizenCached   bool
	sanctionsCached bool
}

// AllCached returns true if both citizen and sanctions records were found in cache.
func (r cacheCheckResult) AllCached() bool {
	return r.citizenCached && r.sanctionsCached
}

// requireConsent checks consent for registry_check purpose.
// This is called atomically within service methods to prevent TOCTOU races.
func (s *Service) requireConsent(ctx context.Context, userID id.UserID) error {
	if s.consentPort == nil {
		return nil
	}
	return s.consentPort.RequireConsent(ctx, userID.String(), "registry_check")
}

// checkCache retrieves cached citizen and sanctions records.
// Returns a cacheCheckResult with records and cache hit flags, or an error.
func (s *Service) checkCache(ctx context.Context, nationalID id.NationalID) (cacheCheckResult, error) {
	var result cacheCheckResult

	if s.cache == nil {
		return result, nil
	}

	if cached, cacheErr := s.cache.FindCitizen(ctx, nationalID, s.regulated); cacheErr == nil {
		result.citizen = cached
		result.citizenCached = true
	} else if !errors.Is(cacheErr, store.ErrNotFound) {
		return cacheCheckResult{}, cacheErr
	}

	if cached, cacheErr := s.cache.FindSanction(ctx, nationalID); cacheErr == nil {
		result.sanction = cached
		result.sanctionsCached = true
	} else if !errors.Is(cacheErr, store.ErrNotFound) {
		return cacheCheckResult{}, cacheErr
	}

	return result, nil
}

// fetchMissing retrieves records not found in cache from the orchestrator.
func (s *Service) fetchMissing(ctx context.Context, nationalID id.NationalID, citizenCached, sanctionsCached bool) (*orchestrator.LookupResult, error) {
	var typesToFetch []providers.ProviderType
	if !citizenCached {
		typesToFetch = append(typesToFetch, providers.ProviderTypeCitizen)
	}
	if !sanctionsCached {
		typesToFetch = append(typesToFetch, providers.ProviderTypeSanctions)
	}

	result, err := s.orchestrator.Lookup(ctx, orchestrator.LookupRequest{
		Types:    typesToFetch,
		Filters:  map[string]string{"national_id": nationalID.String()},
		Strategy: orchestrator.StrategyFallback,
	})
	if err != nil {
		return nil, s.translateOrchestratorError(err, result)
	}
	return result, nil
}

// convertEvidence transforms orchestrator evidence into domain models via domain aggregates.
// Applies regulated mode minimization using the domain aggregate's Minimized() method.
//
// Flow: providers.Evidence → domain aggregate (validates invariants) → models.*Record
func (s *Service) convertEvidence(result *orchestrator.LookupResult) (*models.CitizenRecord, *models.SanctionsRecord, error) {
	var citizenRecord *models.CitizenRecord
	var sanctionRecord *models.SanctionsRecord

	for _, ev := range result.Evidence {
		switch ev.ProviderType {
		case providers.ProviderTypeCitizen:
			verification, err := EvidenceToCitizenVerification(ev)
			if err != nil {
				return nil, nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to convert citizen evidence")
			}
			if s.regulated {
				verification = verification.WithoutNationalID()
			}
			citizenRecord = CitizenVerificationToRecord(verification)
		case providers.ProviderTypeSanctions:
			check, err := EvidenceToSanctionsCheck(ev)
			if err != nil {
				return nil, nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to convert sanctions evidence")
			}
			sanctionRecord = SanctionsCheckToRecord(check)
		}
	}

	return citizenRecord, sanctionRecord, nil
}

// cacheNewlyFetched saves records to cache. Only caches records that weren't already cached.
// Stores the current regulated mode with citizen records for cache invalidation.
// The key parameter is the original lookup key, used to avoid cache collisions when
// records are minimized (regulated mode blanks NationalID in the record).
func (s *Service) cacheNewlyFetched(ctx context.Context, key id.NationalID, citizen *models.CitizenRecord, sanction *models.SanctionsRecord, fromCache cacheCheckResult) {
	if s.cache == nil {
		return
	}
	if !fromCache.citizenCached && citizen != nil {
		_ = s.cache.SaveCitizen(ctx, key, citizen, s.regulated)
	}
	if !fromCache.sanctionsCached && sanction != nil {
		_ = s.cache.SaveSanction(ctx, key, sanction)
	}
}

// Citizen performs a single citizen lookup with cache-through semantics.
//
// The method first checks consent atomically, then checks the cache; on a miss,
// it queries the orchestrator using the fallback strategy and caches successful results.
// If regulated mode is enabled, PII is stripped from the record before returning and caching.
//
// For combined citizen + sanctions lookups, prefer Check() which provides atomic
// transaction semantics ensuring both records are fetched and cached together.
//
// When a tracer is configured, emits a registry.citizen span with cache.hit attribute.
func (s *Service) Citizen(ctx context.Context, userID id.UserID, nationalID id.NationalID) (record *models.CitizenRecord, err error) {
	// Start span if tracer is configured
	ctx, span := s.startSpan(ctx, tracer.SpanRegistryCitizen,
		tracer.String(tracer.AttrNationalID, tracer.HashNationalID(nationalID.String())),
		tracer.Bool(tracer.AttrRegulatedMode, s.regulated),
	)
	defer func() { s.endSpan(span, err) }()

	// Atomic consent check - must succeed before any lookup
	if err = s.requireConsent(ctx, userID); err != nil {
		return nil, err
	}

	// Check cache
	cacheHit := false
	if s.cache != nil {
		if cached, cacheErr := s.cache.FindCitizen(ctx, nationalID, s.regulated); cacheErr == nil {
			cacheHit = true
			if span != nil {
				span.SetAttributes(tracer.Bool(tracer.AttrCacheHit, true))
			}
			return cached, nil
		} else if !errors.Is(cacheErr, store.ErrNotFound) {
			return nil, cacheErr
		}
	}
	if span != nil && !cacheHit {
		span.SetAttributes(tracer.Bool(tracer.AttrCacheHit, false))
	}

	result, err := s.orchestrator.Lookup(ctx, orchestrator.LookupRequest{
		Types: []providers.ProviderType{providers.ProviderTypeCitizen},
		Filters: map[string]string{
			"national_id": nationalID.String(),
		},
		Strategy: orchestrator.StrategyFallback,
	})
	if err != nil {
		return nil, s.translateOrchestratorError(err, result)
	}

	// Find citizen evidence and convert via domain aggregate
	for _, ev := range result.Evidence {
		if ev.ProviderType == providers.ProviderTypeCitizen {
			verification, convErr := EvidenceToCitizenVerification(ev)
			if convErr != nil {
				err = dErrors.Wrap(convErr, dErrors.CodeInternal, "failed to convert citizen evidence")
				return nil, err
			}
			if s.regulated {
				verification = verification.WithoutNationalID()
			}
			record = CitizenVerificationToRecord(verification)
			break
		}
	}

	if record == nil {
		err = s.translateOrchestratorError(providers.ErrAllProvidersFailed, result)
		return nil, err
	}

	if s.cache != nil {
		_ = s.cache.SaveCitizen(ctx, nationalID, record, s.regulated)
	}

	return record, nil
}

// Sanctions performs a single sanctions lookup with cache-through semantics.
//
// The method first checks consent atomically, then checks the cache; on a miss,
// it queries the orchestrator using the fallback strategy and caches successful results.
//
// For combined citizen + sanctions lookups, prefer Check() which provides atomic
// transaction semantics ensuring both records are fetched and cached together.
//
// When a tracer is configured, emits a registry.sanctions span with cache.hit attribute.
func (s *Service) Sanctions(ctx context.Context, userID id.UserID, nationalID id.NationalID) (record *models.SanctionsRecord, err error) {
	// Start span if tracer is configured
	ctx, span := s.startSpan(ctx, tracer.SpanRegistrySanction,
		tracer.String(tracer.AttrNationalID, tracer.HashNationalID(nationalID.String())),
	)
	defer func() { s.endSpan(span, err) }()

	// Atomic consent check - must succeed before any lookup
	if err = s.requireConsent(ctx, userID); err != nil {
		return nil, err
	}

	// Check cache
	cacheHit := false
	if s.cache != nil {
		if cached, cacheErr := s.cache.FindSanction(ctx, nationalID); cacheErr == nil {
			cacheHit = true
			if span != nil {
				span.SetAttributes(tracer.Bool(tracer.AttrCacheHit, true))
			}
			return cached, nil
		} else if !errors.Is(cacheErr, store.ErrNotFound) {
			return nil, cacheErr
		}
	}
	if span != nil && !cacheHit {
		span.SetAttributes(tracer.Bool(tracer.AttrCacheHit, false))
	}

	result, err := s.orchestrator.Lookup(ctx, orchestrator.LookupRequest{
		Types: []providers.ProviderType{providers.ProviderTypeSanctions},
		Filters: map[string]string{
			"national_id": nationalID.String(),
		},
		Strategy: orchestrator.StrategyFallback,
	})
	if err != nil {
		return nil, s.translateOrchestratorError(err, result)
	}

	// Find sanctions evidence and convert via domain aggregate
	for _, ev := range result.Evidence {
		if ev.ProviderType == providers.ProviderTypeSanctions {
			check, convErr := EvidenceToSanctionsCheck(ev)
			if convErr != nil {
				err = dErrors.Wrap(convErr, dErrors.CodeInternal, "failed to convert sanctions evidence")
				return nil, err
			}
			record = SanctionsCheckToRecord(check)
			break
		}
	}

	if record == nil {
		err = s.translateOrchestratorError(providers.ErrAllProvidersFailed, result)
		return nil, err
	}

	if s.cache != nil {
		_ = s.cache.SaveSanction(ctx, nationalID, record)
	}

	return record, nil
}

// translateOrchestratorError converts orchestrator/provider errors to domain errors.
//
// This method implements the error boundary between infrastructure (providers/orchestrator)
// and domain layers. It first checks for provider-specific errors in the result, then
// handles orchestrator sentinel errors, ensuring no internal error details leak to callers.
func (s *Service) translateOrchestratorError(err error, result *orchestrator.LookupResult) error {
	// First check for provider-specific errors in the result
	if result != nil && len(result.Errors) > 0 {
		for _, provErr := range result.Errors {
			if translated := s.translateProviderError(provErr); translated != nil {
				return translated
			}
		}
	}

	// Handle sentinel errors from orchestrator
	if errors.Is(err, providers.ErrAllProvidersFailed) {
		return dErrors.New(dErrors.CodeInternal, "all registry providers failed")
	}
	if errors.Is(err, providers.ErrNoProvidersAvailable) {
		return dErrors.New(dErrors.CodeInternal, "no registry providers available")
	}
	if errors.Is(err, providers.ErrProviderNotFound) {
		return dErrors.New(dErrors.CodeInternal, "registry provider not found")
	}

	return s.translateProviderError(err)
}

// translateProviderError converts provider-specific errors to domain errors.
//
// Maps the normalized ErrorCategory from providers to appropriate domain error codes:
//   - ErrorTimeout → CodeTimeout (retryable by caller)
//   - ErrorNotFound → CodeNotFound (record doesn't exist)
//   - ErrorBadData → CodeBadRequest (caller provided invalid input)
//   - All others → CodeInternal (infrastructure failures hidden from caller)
func (s *Service) translateProviderError(err error) error {
	var pe *providers.ProviderError
	if errors.As(err, &pe) {
		switch pe.Category {
		case providers.ErrorTimeout:
			return dErrors.New(dErrors.CodeTimeout, "registry lookup timed out")
		case providers.ErrorNotFound:
			return dErrors.New(dErrors.CodeNotFound, "citizen record not found")
		case providers.ErrorAuthentication:
			return dErrors.New(dErrors.CodeInternal, "registry authentication failed")
		case providers.ErrorRateLimited:
			return dErrors.New(dErrors.CodeInternal, "registry rate limited")
		case providers.ErrorProviderOutage:
			return dErrors.New(dErrors.CodeInternal, "registry unavailable")
		case providers.ErrorBadData:
			return dErrors.New(dErrors.CodeBadRequest, pe.Message)
		default:
			return dErrors.New(dErrors.CodeInternal, "registry lookup failed")
		}
	}
	return dErrors.Wrap(err, dErrors.CodeInternal, "registry lookup failed")
}

// -----------------------------------------------------------------------------
// Tracing helpers
// -----------------------------------------------------------------------------

// startSpan starts a new span if a tracer is configured.
// Returns the context and span (which may be nil if no tracer is set).
func (s *Service) startSpan(ctx context.Context, name string, attrs ...tracer.Attribute) (context.Context, tracer.Span) {
	if s.tracer == nil {
		return ctx, nil
	}
	return s.tracer.Start(ctx, name, attrs...)
}

// endSpan ends a span if it's not nil.
func (s *Service) endSpan(span tracer.Span, err error) {
	if span != nil {
		span.End(err)
	}
}

// checkCacheWithTracing performs cache lookup with tracing annotations.
// Sets cache.hit attributes on the parent span for both citizen and sanctions lookups.
func (s *Service) checkCacheWithTracing(ctx context.Context, nationalID id.NationalID, parentSpan tracer.Span) (cacheCheckResult, error) {
	result, err := s.checkCache(ctx, nationalID)
	if err != nil {
		return result, err
	}

	// Annotate parent span with cache hit/miss for each lookup type
	if parentSpan != nil {
		parentSpan.SetAttributes(
			tracer.Bool("cache.citizen.hit", result.citizenCached),
			tracer.Bool("cache.sanctions.hit", result.sanctionsCached),
		)
	}

	return result, nil
}

// fetchMissingWithTracing fetches missing records with child spans for each lookup type.
func (s *Service) fetchMissingWithTracing(ctx context.Context, nationalID id.NationalID, cached cacheCheckResult) (*orchestrator.LookupResult, error) {
	var typesToFetch []providers.ProviderType

	// Fetch citizen with child span if not cached
	if !cached.citizenCached {
		typesToFetch = append(typesToFetch, providers.ProviderTypeCitizen)
	}

	// Fetch sanctions with child span if not cached
	if !cached.sanctionsCached {
		typesToFetch = append(typesToFetch, providers.ProviderTypeSanctions)
	}

	if len(typesToFetch) == 0 {
		return &orchestrator.LookupResult{}, nil
	}

	// Start child span for the combined fetch operation
	ctx, span := s.startSpan(ctx, "registry.fetch")
	defer func() { s.endSpan(span, nil) }()

	result, err := s.orchestrator.Lookup(ctx, orchestrator.LookupRequest{
		Types:    typesToFetch,
		Filters:  map[string]string{"national_id": nationalID.String()},
		Strategy: orchestrator.StrategyFallback,
	})
	if err != nil {
		s.endSpan(span, err)
		return nil, s.translateOrchestratorError(err, result)
	}
	return result, nil
}
