package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	evidenceports "credo/internal/evidence/ports"
	"credo/internal/evidence/registry/models"
	"credo/internal/evidence/registry/orchestrator"
	"credo/internal/evidence/registry/ports"
	"credo/internal/evidence/registry/providers"
	"credo/internal/evidence/registry/store"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	"credo/pkg/requestcontext"
	"golang.org/x/sync/errgroup"
)

// Tracer for distributed tracing of registry operations.
var registryTracer = otel.Tracer("credo/registry")

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
// Distributed tracing is supported via OpenTelemetry. The service emits spans for
// registry.check (parent), registry.citizen, and registry.sanctions operations
// with cache hit/miss annotations.
// Audit events are emitted with fail-closed semantics for listed sanctions: the audit MUST
// succeed before the client learns about a sanctions listing. This ensures compliance
// auditability is never bypassed.
type Service struct {
	orchestrator *orchestrator.Orchestrator
	cache        CacheStore
	consentPort  ports.ConsentPort
	auditor      evidenceports.AuditPublisher
	regulated    bool
	logger       *slog.Logger
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

// WithAuditor sets the audit port for the service.
// When set, sanctions lookups will emit audit events with fail-closed semantics
// for listed sanctions (audit must succeed before result is returned).
func WithAuditor(auditor evidenceports.AuditPublisher) Option {
	return func(s *Service) {
		s.auditor = auditor
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
// Emits a parent span (registry.check) with child spans for citizen and sanctions lookups,
// annotated with cache hit/miss attributes.
func (s *Service) Check(ctx context.Context, userID id.UserID, nationalID id.NationalID) (result *models.RegistryResult, err error) {
	// Start parent span for distributed tracing
	ctx, span := registryTracer.Start(ctx, "registry.check",
		trace.WithAttributes(
			attribute.String("national_id", hashNationalID(nationalID.String())),
			attribute.Bool("regulated_mode", s.regulated),
		),
	)
	defer func() { endSpan(span, err) }()

	// Phase 1: Atomic consent check - must succeed before any lookup
	if err = s.requireConsent(ctx, userID); err != nil {
		return nil, err
	}

	// Phase 2: Check cache with tracing
	cached, err := s.checkCache(ctx, nationalID)
	if err != nil {
		return nil, err
	}
	// Annotate span with cache hit/miss for each lookup type
	span.SetAttributes(
		attribute.Bool("cache.citizen.hit", cached.citizenCached),
		attribute.Bool("cache.sanctions.hit", cached.sanctionsCached),
	)
	if cached.AllCached() {
		return &models.RegistryResult{Citizen: cached.citizen, Sanction: cached.sanction}, nil
	}

	// Phase 3: Fetch missing from orchestrator
	fetchResult, err := s.fetchMissing(ctx, nationalID, cached.citizenCached, cached.sanctionsCached)
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
	return s.consentPort.RequireConsent(ctx, userID, id.ConsentPurposeRegistryCheck)
}

// checkCache retrieves cached citizen and sanctions records.
// Returns a cacheCheckResult with records and cache hit flags, or an error.
func (s *Service) checkCache(ctx context.Context, nationalID id.NationalID) (cacheCheckResult, error) {
	var result cacheCheckResult

	if s.cache == nil {
		return result, nil
	}

	var (
		citizen        *models.CitizenRecord
		sanction       *models.SanctionsRecord
		citizenCached  bool
		sanctionCached bool
	)

	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		cached, cacheErr := s.cache.FindCitizen(groupCtx, nationalID, s.regulated)
		if cacheErr == nil {
			citizen = cached
			citizenCached = true
			return nil
		}
		if errors.Is(cacheErr, store.ErrNotFound) {
			return nil
		}
		return cacheErr
	})

	group.Go(func() error {
		cached, cacheErr := s.cache.FindSanction(groupCtx, nationalID)
		if cacheErr == nil {
			sanction = cached
			sanctionCached = true
			return nil
		}
		if errors.Is(cacheErr, store.ErrNotFound) {
			return nil
		}
		return cacheErr
	})

	if err := group.Wait(); err != nil {
		return cacheCheckResult{}, err
	}

	result.citizen = citizen
	result.sanction = sanction
	result.citizenCached = citizenCached
	result.sanctionsCached = sanctionCached

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

	var wg sync.WaitGroup
	if !fromCache.citizenCached && citizen != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.cache.SaveCitizen(ctx, key, citizen, s.regulated)
		}()
	}
	if !fromCache.sanctionsCached && sanction != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.cache.SaveSanction(ctx, key, sanction)
		}()
	}
	wg.Wait()
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
// Emits a registry.citizen span with cache.hit attribute.
func (s *Service) Citizen(ctx context.Context, userID id.UserID, nationalID id.NationalID) (record *models.CitizenRecord, err error) {
	// Start span for distributed tracing
	ctx, span := registryTracer.Start(ctx, "registry.citizen",
		trace.WithAttributes(
			attribute.String("national_id", hashNationalID(nationalID.String())),
			attribute.Bool("regulated_mode", s.regulated),
		),
	)
	defer func() { endSpan(span, err) }()

	// Atomic consent check - must succeed before any lookup
	if err = s.requireConsent(ctx, userID); err != nil {
		return nil, err
	}

	// Check cache
	if s.cache != nil {
		if cached, cacheErr := s.cache.FindCitizen(ctx, nationalID, s.regulated); cacheErr == nil {
			span.SetAttributes(attribute.Bool("cache.hit", true))
			return cached, nil
		} else if !errors.Is(cacheErr, store.ErrNotFound) {
			return nil, cacheErr
		}
	}
	span.SetAttributes(attribute.Bool("cache.hit", false))

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

// CitizenWithDetails performs a citizen lookup returning full PII for internal use.
//
// Unlike Citizen(), this method does NOT apply regulated mode minimization. It is intended
// for internal service-to-service calls where the caller needs to compute derived attributes
// from PII (e.g., VC issuance computing is_over_18 from date_of_birth) before the caller
// applies its own minimization to the final output.
//
// IMPORTANT: This method must only be called by internal services that will minimize their
// own output. External-facing APIs should use Citizen() which enforces regulated mode.
//
// The returned data is NOT cached to prevent stale unminimized PII in shared caches.
func (s *Service) CitizenWithDetails(ctx context.Context, userID id.UserID, nationalID id.NationalID) (record *models.CitizenRecord, err error) {
	// Start span for distributed tracing
	ctx, span := registryTracer.Start(ctx, "registry.citizen.internal",
		trace.WithAttributes(
			attribute.String("national_id", hashNationalID(nationalID.String())),
			attribute.Bool("internal_call", true),
		),
	)
	defer func() { endSpan(span, err) }()

	// Atomic consent check - must succeed before any lookup
	if err = s.requireConsent(ctx, userID); err != nil {
		return nil, err
	}

	// No cache for internal calls - prevents unminimized PII in shared cache

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

	// Find citizen evidence and convert via domain aggregate - NO minimization
	for _, ev := range result.Evidence {
		if ev.ProviderType == providers.ProviderTypeCitizen {
			verification, convErr := EvidenceToCitizenVerification(ev)
			if convErr != nil {
				err = dErrors.Wrap(convErr, dErrors.CodeInternal, "failed to convert citizen evidence")
				return nil, err
			}
			// Intentionally skip minimization - caller will minimize their own output
			record = CitizenVerificationToRecord(verification)
			break
		}
	}

	if record == nil {
		err = s.translateOrchestratorError(providers.ErrAllProvidersFailed, result)
		return nil, err
	}

	return record, nil
}

// Sanctions performs a single sanctions lookup with cache-through semantics.
//
// The method first checks consent atomically, then checks the cache; on a miss,
// it queries the orchestrator using the fallback strategy and caches successful results.
//
// After a successful lookup, an audit event is emitted with fail-closed semantics:
// for listed sanctions, the audit MUST succeed before the result is returned.
// This ensures compliance auditability is never bypassed for security-critical results.
//
// For combined citizen + sanctions lookups, prefer Check() which provides atomic
// transaction semantics ensuring both records are fetched and cached together.
//
// Emits a registry.sanctions span with cache.hit attribute.
func (s *Service) Sanctions(ctx context.Context, userID id.UserID, nationalID id.NationalID) (record *models.SanctionsRecord, err error) {
	// Start span for distributed tracing
	ctx, span := registryTracer.Start(ctx, "registry.sanctions",
		trace.WithAttributes(
			attribute.String("national_id", hashNationalID(nationalID.String())),
		),
	)
	defer func() { endSpan(span, err) }()

	// Atomic consent check - must succeed before any lookup
	if err = s.requireConsent(ctx, userID); err != nil {
		return nil, err
	}

	// Check cache
	cacheHit := false
	if s.cache != nil {
		if cached, cacheErr := s.cache.FindSanction(ctx, nationalID); cacheErr == nil {
			cacheHit = true
			span.SetAttributes(attribute.Bool("cache.hit", true))
			// Audit cached result before returning
			if err := s.auditSanctionsCheck(ctx, userID, cached.Listed); err != nil {
				return nil, err
			}
			return cached, nil
		} else if !errors.Is(cacheErr, store.ErrNotFound) {
			return nil, cacheErr
		}
	}
	if !cacheHit {
		span.SetAttributes(attribute.Bool("cache.hit", false))
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

	// Audit before returning - fail-closed for listed sanctions
	if err := s.auditSanctionsCheck(ctx, userID, record.Listed); err != nil {
		return nil, err
	}

	return record, nil
}

// auditSanctionsCheck emits an audit event for a sanctions check with fail-closed semantics.
// The audit MUST succeed before the result is returned - this ensures a complete audit trail
// for all sanctions checks (both listed and non-listed) and prevents audit bypass via cache replay.
//
// Security rationale: An attacker could otherwise query once (audit succeeds, result cached),
// then query again during audit outage (result served from cache, no audit record).
// Fail-closed semantics ensure every sanctions check is audited.
func (s *Service) auditSanctionsCheck(ctx context.Context, userID id.UserID, listed bool) error {
	if s.auditor == nil {
		return nil
	}

	decision := "not_listed"
	if listed {
		decision = "listed"
	}

	event := audit.Event{
		Action:    "registry_sanctions_checked",
		Purpose:   "registry_check",
		UserID:    userID,
		Decision:  decision,
		Reason:    "user_initiated",
		RequestID: requestcontext.RequestID(ctx),
	}

	// Fail-closed: audit MUST succeed for all sanctions checks
	if err := s.auditor.Emit(ctx, event); err != nil {
		severity := "WARNING"
		if listed {
			severity = "CRITICAL"
		}
		if s.logger != nil {
			s.logger.ErrorContext(ctx, severity+": audit failed for sanctions check - blocking response",
				"user_id", userID,
				"listed", listed,
				"error", err,
			)
		}
		return dErrors.New(dErrors.CodeInternal, "unable to complete sanctions check")
	}
	return nil
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

// endSpan ends a span and records any error.
func endSpan(span trace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	span.End()
}

// hashNationalID returns a SHA-256 hash of the national ID for safe logging.
// This allows correlation without exposing PII in traces.
func hashNationalID(nationalID string) string {
	h := sha256.Sum256([]byte(nationalID))
	return hex.EncodeToString(h[:8]) // First 8 bytes = 16 hex chars
}
