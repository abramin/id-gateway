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

func (s *Service) Check(ctx context.Context, nationalID string) (*models.RegistryResult, error) {
	citizen, err := s.Citizen(ctx, nationalID)
	if err != nil {
		return nil, err
	}
	sanctions, err := s.Sanctions(ctx, nationalID)
	if err != nil {
		return nil, err
	}
	return &models.RegistryResult{
		Citizen:  citizen,
		Sanction: sanctions,
	}, nil
}

func (s *Service) Citizen(ctx context.Context, nationalID string) (*models.CitizenRecord, error) {
	if s.cache != nil {
		if cached, err := s.cache.FindCitizen(ctx, nationalID); err == nil {
			return cached, nil
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	record, err := s.citizens.Lookup(ctx, nationalID)
	if err != nil {
		return nil, s.translateProviderError(err)
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

func (s *Service) Sanctions(ctx context.Context, nationalID string) (*models.SanctionsRecord, error) {
	if s.cache != nil {
		if cached, err := s.cache.FindSanction(ctx, nationalID); err == nil {
			return cached, nil
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	record, err := s.sanctions.Check(ctx, nationalID)
	if err != nil {
		return nil, s.translateProviderError(err)
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
