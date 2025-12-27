package service

import (
	"context"
	"errors"
	"log/slog"

	"credo/internal/evidence/registry/models"
	"credo/internal/evidence/registry/orchestrator"
	"credo/internal/evidence/registry/providers"
	"credo/internal/evidence/registry/store"
	dErrors "credo/pkg/domain-errors"
)

// Service coordinates registry lookups with caching and optional minimisation.
type Service struct {
	orchestrator *orchestrator.Orchestrator
	cache        CacheStore
	regulated    bool
	logger       *slog.Logger
}

// CacheStore defines the interface for registry caching operations
type CacheStore interface {
	FindCitizen(ctx context.Context, nationalID string) (*models.CitizenRecord, error)
	SaveCitizen(ctx context.Context, record *models.CitizenRecord) error
	FindSanction(ctx context.Context, nationalID string) (*models.SanctionsRecord, error)
	SaveSanction(ctx context.Context, record *models.SanctionsRecord) error
}

// Option configures the Service.
type Option func(*Service)

// WithLogger sets the logger for the service.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Service) {
		s.logger = logger
	}
}

// New creates a new registry service using the orchestrator pattern.
func New(orch *orchestrator.Orchestrator, cache CacheStore, regulated bool, opts ...Option) *Service {
	s := &Service{
		orchestrator: orch,
		cache:        cache,
		regulated:    regulated,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Check performs atomic citizen and sanctions lookups with transaction-like semantics.
// Both lookups must succeed before either result is cached. If one fails, no partial
// state is cached, ensuring consistency on retry.
func (s *Service) Check(ctx context.Context, nationalID string) (*models.RegistryResult, error) {
	// Phase 1: Check cache
	citizen, sanction, citizenCached, sanctionsCached, err := s.checkCache(ctx, nationalID)
	if err != nil {
		return nil, err
	}
	if citizenCached && sanctionsCached {
		return &models.RegistryResult{Citizen: citizen, Sanction: sanction}, nil
	}

	// Phase 2: Fetch missing from orchestrator
	result, err := s.fetchMissing(ctx, nationalID, citizenCached, sanctionsCached)
	if err != nil {
		return nil, err
	}

	// Convert evidence to domain models
	fetchedCitizen, fetchedSanction, err := s.convertEvidence(result)
	if err != nil {
		return nil, err
	}

	// Merge cached and fetched records
	if !citizenCached {
		citizen = fetchedCitizen
	}
	if !sanctionsCached {
		sanction = fetchedSanction
	}

	// Validate we got all required evidence
	if citizen == nil || sanction == nil {
		return nil, s.translateOrchestratorError(providers.ErrAllProvidersFailed, result)
	}

	// Phase 3: Atomic cache commit - only cache if both lookups succeeded
	s.commitCache(ctx, citizen, sanction, citizenCached, sanctionsCached)

	return &models.RegistryResult{Citizen: citizen, Sanction: sanction}, nil
}

// checkCache retrieves cached citizen and sanctions records.
// Returns the records (if cached), flags indicating cache hits, and any error.
func (s *Service) checkCache(ctx context.Context, nationalID string) (
	citizen *models.CitizenRecord,
	sanction *models.SanctionsRecord,
	citizenCached, sanctionsCached bool,
	err error,
) {
	if s.cache == nil {
		return nil, nil, false, false, nil
	}

	if cached, cacheErr := s.cache.FindCitizen(ctx, nationalID); cacheErr == nil {
		citizen = cached
		citizenCached = true
	} else if !errors.Is(cacheErr, store.ErrNotFound) {
		return nil, nil, false, false, cacheErr
	}

	if cached, cacheErr := s.cache.FindSanction(ctx, nationalID); cacheErr == nil {
		sanction = cached
		sanctionsCached = true
	} else if !errors.Is(cacheErr, store.ErrNotFound) {
		return nil, nil, false, false, cacheErr
	}

	return citizen, sanction, citizenCached, sanctionsCached, nil
}

// fetchMissing retrieves records not found in cache from the orchestrator.
func (s *Service) fetchMissing(ctx context.Context, nationalID string, citizenCached, sanctionsCached bool) (*orchestrator.LookupResult, error) {
	var typesToFetch []providers.ProviderType
	if !citizenCached {
		typesToFetch = append(typesToFetch, providers.ProviderTypeCitizen)
	}
	if !sanctionsCached {
		typesToFetch = append(typesToFetch, providers.ProviderTypeSanctions)
	}

	result, err := s.orchestrator.Lookup(ctx, orchestrator.LookupRequest{
		Types:    typesToFetch,
		Filters:  map[string]string{"national_id": nationalID},
		Strategy: orchestrator.StrategyFallback,
	})
	if err != nil {
		return nil, s.translateOrchestratorError(err, result)
	}
	return result, nil
}

// convertEvidence transforms orchestrator evidence into domain models.
// Applies regulated mode minimization to citizen records.
func (s *Service) convertEvidence(result *orchestrator.LookupResult) (*models.CitizenRecord, *models.SanctionsRecord, error) {
	var citizen *models.CitizenRecord
	var sanction *models.SanctionsRecord

	for _, ev := range result.Evidence {
		switch ev.ProviderType {
		case providers.ProviderTypeCitizen:
			record := EvidenceToCitizenRecord(ev)
			if record == nil {
				return nil, nil, dErrors.New(dErrors.CodeInternal, "failed to convert citizen evidence")
			}
			if s.regulated {
				minimized := models.MinimizeCitizenRecord(*record)
				record = &minimized
			}
			citizen = record
		case providers.ProviderTypeSanctions:
			record := EvidenceToSanctionsRecord(ev)
			if record == nil {
				return nil, nil, dErrors.New(dErrors.CodeInternal, "failed to convert sanctions evidence")
			}
			sanction = record
		}
	}

	return citizen, sanction, nil
}

// commitCache saves records to cache. Only caches records that weren't already cached.
func (s *Service) commitCache(ctx context.Context, citizen *models.CitizenRecord, sanction *models.SanctionsRecord, citizenCached, sanctionsCached bool) {
	if s.cache == nil {
		return
	}
	if !citizenCached && citizen != nil {
		_ = s.cache.SaveCitizen(ctx, citizen)
	}
	if !sanctionsCached && sanction != nil {
		_ = s.cache.SaveSanction(ctx, sanction)
	}
}

// Citizen performs a single citizen lookup with caching.
// For combined lookups, prefer Check() which provides atomic transaction semantics.
func (s *Service) Citizen(ctx context.Context, nationalID string) (*models.CitizenRecord, error) {
	if s.cache != nil {
		if cached, err := s.cache.FindCitizen(ctx, nationalID); err == nil {
			return cached, nil
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}

	result, err := s.orchestrator.Lookup(ctx, orchestrator.LookupRequest{
		Types: []providers.ProviderType{providers.ProviderTypeCitizen},
		Filters: map[string]string{
			"national_id": nationalID,
		},
		Strategy: orchestrator.StrategyFallback,
	})
	if err != nil {
		return nil, s.translateOrchestratorError(err, result)
	}

	// Find citizen evidence in result
	var record *models.CitizenRecord
	for _, ev := range result.Evidence {
		if ev.ProviderType == providers.ProviderTypeCitizen {
			record = EvidenceToCitizenRecord(ev)
			break
		}
	}

	if record == nil {
		return nil, s.translateOrchestratorError(providers.ErrAllProvidersFailed, result)
	}

	if s.regulated {
		minimized := models.MinimizeCitizenRecord(*record)
		record = &minimized
	}

	if s.cache != nil {
		_ = s.cache.SaveCitizen(ctx, record)
	}

	return record, nil
}

// Sanctions performs a single sanctions lookup with caching.
// For combined lookups, prefer Check() which provides atomic transaction semantics.
func (s *Service) Sanctions(ctx context.Context, nationalID string) (*models.SanctionsRecord, error) {
	if s.cache != nil {
		if cached, err := s.cache.FindSanction(ctx, nationalID); err == nil {
			return cached, nil
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}

	result, err := s.orchestrator.Lookup(ctx, orchestrator.LookupRequest{
		Types: []providers.ProviderType{providers.ProviderTypeSanctions},
		Filters: map[string]string{
			"national_id": nationalID,
		},
		Strategy: orchestrator.StrategyFallback,
	})
	if err != nil {
		return nil, s.translateOrchestratorError(err, result)
	}

	// Find sanctions evidence in result
	var record *models.SanctionsRecord
	for _, ev := range result.Evidence {
		if ev.ProviderType == providers.ProviderTypeSanctions {
			record = EvidenceToSanctionsRecord(ev)
			break
		}
	}

	if record == nil {
		return nil, s.translateOrchestratorError(providers.ErrAllProvidersFailed, result)
	}

	if s.cache != nil {
		_ = s.cache.SaveSanction(ctx, record)
	}

	return record, nil
}

// translateOrchestratorError converts orchestrator/provider errors to domain errors.
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
