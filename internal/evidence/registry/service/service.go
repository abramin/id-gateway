package service

import (
	"context"
	"errors"
	"log/slog"

	"credo/internal/evidence/registry/models"
	"credo/internal/evidence/registry/ports"
	"credo/internal/evidence/registry/providers"
	"credo/internal/evidence/registry/store"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	"credo/pkg/platform/middleware/request"
)

// Service coordinates registry lookups with caching and optional minimisation.
type Service struct {
	citizens  CitizenClient
	sanctions SanctionsClient
	cache     CacheStore
	regulated bool
	auditor   ports.AuditPort
	logger    *slog.Logger
}

// CitizenClient defines the interface for citizen registry lookups
type CitizenClient interface {
	Lookup(ctx context.Context, nationalID string) (*models.CitizenRecord, error)
}

// SanctionsClient defines the interface for sanctions registry lookups
type SanctionsClient interface {
	Check(ctx context.Context, nationalID string) (*models.SanctionsRecord, error)
}

// CacheStore defines the interface for registry caching operations
type CacheStore interface {
	FindCitizen(ctx context.Context, nationalID string) (*models.CitizenRecord, error)
	SaveCitizen(ctx context.Context, record *models.CitizenRecord) error
	FindSanction(ctx context.Context, nationalID string) (*models.SanctionsRecord, error)
	SaveSanction(ctx context.Context, record *models.SanctionsRecord) error
}

// ServiceOption configures the Service.
type ServiceOption func(*Service)

// WithAuditPort sets the audit publisher for the service.
func WithAuditPort(auditor ports.AuditPort) ServiceOption {
	return func(s *Service) {
		s.auditor = auditor
	}
}

// WithLogger sets the logger for the service.
func WithLogger(logger *slog.Logger) ServiceOption {
	return func(s *Service) {
		s.logger = logger
	}
}

func NewService(citizens CitizenClient, sanctions SanctionsClient, cache CacheStore, regulated bool, opts ...ServiceOption) *Service {
	s := &Service{
		citizens:  citizens,
		sanctions: sanctions,
		cache:     cache,
		regulated: regulated,
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
	// Phase 1: Check cache for both records
	var citizenCached, sanctionsCached bool
	var citizen *models.CitizenRecord
	var sanction *models.SanctionsRecord

	if s.cache != nil {
		if cached, err := s.cache.FindCitizen(ctx, nationalID); err == nil {
			citizen = cached
			citizenCached = true
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}

		if cached, err := s.cache.FindSanction(ctx, nationalID); err == nil {
			sanction = cached
			sanctionsCached = true
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}

	// Phase 2: Fetch missing records from providers (without caching yet)
	if !citizenCached {
		record, err := s.lookupCitizen(ctx, nationalID)
		if err != nil {
			return nil, err
		}
		citizen = record
	}

	if !sanctionsCached {
		record, err := s.lookupSanctions(ctx, nationalID)
		if err != nil {
			// Citizen lookup succeeded but sanctions failed - don't cache citizen
			return nil, err
		}
		sanction = record
	}

	// Phase 3: Atomic cache commit - only cache if both lookups succeeded
	if s.cache != nil {
		if !citizenCached {
			_ = s.cache.SaveCitizen(ctx, citizen)
		}
		if !sanctionsCached {
			_ = s.cache.SaveSanction(ctx, sanction)
		}
	}

	return &models.RegistryResult{
		Citizen:  citizen,
		Sanction: sanction,
	}, nil
}

// lookupCitizen fetches from provider and applies minimization, but does NOT cache.
// Used by Check() for atomic transaction semantics.
func (s *Service) lookupCitizen(ctx context.Context, nationalID string) (*models.CitizenRecord, error) {
	record, err := s.citizens.Lookup(ctx, nationalID)
	if err != nil {
		return nil, s.translateProviderError(err)
	}
	if s.regulated {
		minimized := models.MinimizeCitizenRecord(*record)
		record = &minimized
	}
	return record, nil
}

// lookupSanctions fetches from provider but does NOT cache.
// Used by Check() for atomic transaction semantics.
func (s *Service) lookupSanctions(ctx context.Context, nationalID string) (*models.SanctionsRecord, error) {
	record, err := s.sanctions.Check(ctx, nationalID)
	if err != nil {
		return nil, s.translateProviderError(err)
	}
	return record, nil
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
	record, err := s.lookupCitizen(ctx, nationalID)
	if err != nil {
		return nil, err
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
	record, err := s.lookupSanctions(ctx, nationalID)
	if err != nil {
		return nil, err
	}
	if s.cache != nil {
		_ = s.cache.SaveSanction(ctx, record)
	}
	return record, nil
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

// emitAudit publishes an audit event. Failures are logged but don't fail the operation.
func (s *Service) emitAudit(ctx context.Context, event audit.Event) {
	if s.auditor == nil {
		return
	}
	// Enrich with RequestID for correlation
	if event.RequestID == "" {
		event.RequestID = request.GetRequestID(ctx)
	}
	if err := s.auditor.Emit(ctx, event); err != nil {
		if s.logger != nil {
			s.logger.ErrorContext(ctx, "failed to emit audit event",
				"error", err,
				"action", event.Action,
				"user_id", event.UserID,
			)
		}
	}
}
