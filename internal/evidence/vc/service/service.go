package service

import (
	"context"
	"log/slog"
	"time"

	registrymodels "credo/internal/evidence/registry/models"
	"credo/internal/evidence/vc/models"
	"credo/internal/evidence/vc/store"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	"credo/pkg/platform/middleware/request"
	requesttime "credo/pkg/platform/middleware/requesttime"
)

// RegistryService defines the registry lookup dependency for VC issuance.
type RegistryService interface {
	Citizen(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*registrymodels.CitizenRecord, error)
}

// ConsentPort enforces consent requirements for VC issuance.
type ConsentPort interface {
	RequireVCIssuance(ctx context.Context, userID id.UserID) error
}

// AuditPublisher emits audit events for credential lifecycle actions.
type AuditPublisher interface {
	Emit(ctx context.Context, event audit.Event) error
}

// Option configures the VC service.
type Option func(*Service)

// Service issues and verifies verifiable credentials using registry evidence.
type Service struct {
	store       store.Store
	registry    RegistryService
	consentPort ConsentPort
	auditor     AuditPublisher
	regulated   bool
	logger      *slog.Logger
}

// NewService creates a VC service with the required dependencies.
func NewService(store store.Store, registry RegistryService, consentPort ConsentPort, regulated bool, opts ...Option) *Service {
	svc := &Service{
		store:       store,
		registry:    registry,
		consentPort: consentPort,
		regulated:   regulated,
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

// WithAuditor configures an audit publisher for the service.
func WithAuditor(auditor AuditPublisher) Option {
	return func(s *Service) {
		s.auditor = auditor
	}
}

// WithLogger configures a logger for the service.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Service) {
		s.logger = logger
	}
}

// Issue issues a new AgeOver18 credential after registry verification.
func (s *Service) Issue(ctx context.Context, req models.IssueRequest) (*models.VerifiableCredential, error) {
	if req.UserID.IsNil() {
		return nil, dErrors.New(dErrors.CodeUnauthorized, "user ID required")
	}
	if req.Type != models.CredentialTypeAgeOver18 {
		return nil, dErrors.New(dErrors.CodeBadRequest, "invalid credential type")
	}
	if req.NationalID.IsNil() {
		return nil, dErrors.New(dErrors.CodeBadRequest, "national_id is required")
	}
	if s.registry == nil {
		return nil, dErrors.New(dErrors.CodeInternal, "registry service unavailable")
	}
	if s.store == nil {
		return nil, dErrors.New(dErrors.CodeInternal, "credential store unavailable")
	}

	if err := s.requireVCIssuanceConsent(ctx, req.UserID); err != nil {
		return nil, err
	}

	record, err := s.registry.Citizen(ctx, req.UserID, req.NationalID)
	if err != nil {
		return nil, err
	}
	if record == nil || !record.Valid {
		return nil, dErrors.New(dErrors.CodeBadRequest, "invalid citizen record")
	}

	birthDate, err := time.Parse("2006-01-02", record.DateOfBirth)
	if err != nil {
		return nil, dErrors.New(dErrors.CodeBadRequest, "invalid citizen record")
	}

	now := requesttime.Now(ctx)
	if !isOver18(birthDate, now) {
		return nil, dErrors.New(dErrors.CodeBadRequest, "User does not meet age requirement")
	}

	claims := models.Claims{
		"is_over_18":   true,
		"verified_via": models.VerifiedViaNationalRegistry,
	}
	claims = models.MinimizeClaims(claims, s.regulated)

	credential := models.VerifiableCredential{
		ID:       models.NewCredentialID(),
		Type:     req.Type,
		Subject:  req.UserID,
		Issuer:   models.IssuerCredo,
		IssuedAt: now,
		Claims:   claims,
	}

	if err := s.store.Save(ctx, credential); err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to store credential")
	}

	s.emitAudit(ctx, credential)

	return &credential, nil
}

// Verify validates an issued credential by ID and returns its stored content.
func (s *Service) Verify(ctx context.Context, credentialID models.CredentialID) (*models.VerifyResult, error) {
	if credentialID == "" {
		return nil, dErrors.New(dErrors.CodeBadRequest, "credential_id is required")
	}
	if s.store == nil {
		return nil, dErrors.New(dErrors.CodeInternal, "credential store unavailable")
	}

	credential, err := s.store.FindByID(ctx, credentialID)
	if err != nil {
		return nil, err
	}

	return &models.VerifyResult{
		Valid:      true,
		Credential: &credential,
	}, nil
}

func (s *Service) requireVCIssuanceConsent(ctx context.Context, userID id.UserID) error {
	if s.consentPort == nil {
		return nil
	}
	return s.consentPort.RequireVCIssuance(ctx, userID)
}

func (s *Service) emitAudit(ctx context.Context, credential models.VerifiableCredential) {
	if s.auditor == nil {
		return
	}

	event := audit.Event{
		Action:    "vc_issued",
		Purpose:   "vc_issuance",
		UserID:    credential.Subject,
		Subject:   credential.ID.String(),
		Decision:  "issued",
		Reason:    "user_initiated",
		RequestID: request.GetRequestID(ctx),
	}

	if err := s.auditor.Emit(ctx, event); err != nil && s.logger != nil {
		s.logger.ErrorContext(ctx, "failed to emit vc_issued audit event",
			"error", err,
			"user_id", credential.Subject,
		)
	}
}

func isOver18(birthDate, now time.Time) bool {
	adultAt := birthDate.UTC().AddDate(18, 0, 0)
	return !now.UTC().Before(adultAt)
}
