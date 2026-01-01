package service

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"credo/internal/evidence/vc/domain/credential"
	"credo/internal/evidence/vc/domain/shared"
	"credo/internal/evidence/vc/models"
	"credo/internal/evidence/vc/ports"
	"credo/internal/evidence/vc/store"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	"credo/pkg/platform/sentinel"
	"credo/pkg/requestcontext"
)

// AuditPublisher emits audit events for credential lifecycle actions.
type AuditPublisher interface {
	Emit(ctx context.Context, event audit.Event) error
}

// Option configures the VC service.
type Option func(*Service)

// Service issues and verifies verifiable credentials using registry evidence.
type Service struct {
	store       store.Store
	registry    ports.RegistryPort
	consentPort ports.ConsentPort
	auditor     AuditPublisher
	regulated   bool
	logger      *slog.Logger
}

// NewService creates a VC service with the required dependencies.
// Panics if required dependencies (store, registry) are nil - fail fast at startup.
func NewService(store store.Store, registry ports.RegistryPort, consentPort ports.ConsentPort, regulated bool, opts ...Option) *Service {
	if store == nil {
		panic("vc.NewService: store is required")
	}
	if registry == nil {
		panic("vc.NewService: registry is required")
	}

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
func (s *Service) Issue(ctx context.Context, req models.IssueRequest) (*models.CredentialRecord, error) {
	if req.UserID.IsNil() {
		return nil, dErrors.New(dErrors.CodeUnauthorized, "user ID required")
	}
	if req.Type != models.CredentialTypeAgeOver18 {
		return nil, dErrors.New(dErrors.CodeBadRequest, "invalid credential type")
	}
	if req.NationalID.IsNil() {
		return nil, dErrors.New(dErrors.CodeBadRequest, "national_id is required")
	}

	if err := s.requireVCIssuanceConsent(ctx, req.UserID); err != nil {
		return nil, err
	}

	record, err := s.registry.Citizen(ctx, req.UserID, req.NationalID)
	if err != nil {
		return nil, sanitizeExternalError(err, "registry lookup failed")
	}
	if record == nil || !record.Valid {
		return nil, dErrors.New(dErrors.CodeBadRequest, "invalid citizen record")
	}

	birthDate, err := time.Parse("2006-01-02", record.DateOfBirth)
	if err != nil {
		return nil, dErrors.New(dErrors.CodeBadRequest, "invalid citizen record")
	}

	now := requestcontext.Now(ctx)
	if !isOver18(birthDate, now) {
		return nil, dErrors.New(dErrors.CodeBadRequest, "User does not meet age requirement")
	}

	// Build typed claims via domain value object
	claims := credential.NewAgeOver18Claims(true, models.VerifiedViaNationalRegistry)

	issuedAt, err := shared.NewIssuedAt(now)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to create issuance timestamp")
	}

	// Create domain aggregate
	cred, err := credential.New(
		models.NewCredentialID(),
		req.Type,
		req.UserID,
		models.IssuerCredo,
		issuedAt,
		claims,
	)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to create credential")
	}

	// Apply minimization in regulated mode
	if s.regulated {
		cred = cred.Minimized()
	}

	// Convert to infrastructure model for storage
	vcModel := credential.ToModel(cred)

	if err := s.store.Save(ctx, vcModel); err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to store credential")
	}

	s.emitAudit(ctx, vcModel)

	return &vcModel, nil
}

// Verify validates an issued credential by ID and returns its stored content.
func (s *Service) Verify(ctx context.Context, credentialID models.CredentialID) (*models.VerifyResult, error) {
	if credentialID == "" {
		return nil, dErrors.New(dErrors.CodeBadRequest, "credential_id is required")
	}

	cred, err := s.store.FindByID(ctx, credentialID)
	if err != nil {
		// Translate sentinel errors to domain errors at service boundary
		if errors.Is(err, sentinel.ErrNotFound) {
			return nil, dErrors.New(dErrors.CodeNotFound, "credential not found")
		}
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to retrieve credential")
	}

	result := &models.VerifyResult{
		Valid:      true,
		Credential: &cred,
	}

	s.emitVerifyAudit(ctx, cred)

	return result, nil
}

func (s *Service) requireVCIssuanceConsent(ctx context.Context, userID id.UserID) error {
	if s.consentPort == nil {
		return dErrors.New(dErrors.CodeInternal, "consent service unavailable")
	}
	if err := s.consentPort.RequireVCIssuance(ctx, userID); err != nil {
		return sanitizeExternalError(err, "consent check failed")
	}
	return nil
}

func (s *Service) emitAudit(ctx context.Context, credential models.CredentialRecord) {
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
		RequestID: requestcontext.RequestID(ctx),
	}

	if err := s.auditor.Emit(ctx, event); err != nil && s.logger != nil {
		s.logger.ErrorContext(ctx, "failed to emit vc_issued audit event",
			"error", err,
			"user_id", credential.Subject,
		)
	}
}

func (s *Service) emitVerifyAudit(ctx context.Context, credential models.CredentialRecord) {
	// TODO: this should probably error if auditor is nil?
	if s.auditor == nil {
		return
	}

	event := audit.Event{
		Action:    "vc_verified",
		Purpose:   "vc_verification",
		UserID:    credential.Subject,
		Subject:   credential.ID.String(),
		Decision:  "verified",
		Reason:    "user_initiated",
		RequestID: requestcontext.RequestID(ctx),
	}

	if err := s.auditor.Emit(ctx, event); err != nil && s.logger != nil {
		s.logger.ErrorContext(ctx, "failed to emit vc_verified audit event",
			"error", err,
			"user_id", credential.Subject,
		)
	}
}

func isOver18(birthDate, now time.Time) bool {
	adultAt := birthDate.UTC().AddDate(18, 0, 0)
	return !now.UTC().Before(adultAt)
}

func sanitizeExternalError(err error, msg string) error {
	if err == nil {
		return nil
	}

	var domainErr *dErrors.Error
	if errors.As(err, &domainErr) {
		if domainErr.Code == dErrors.CodeInternal {
			return dErrors.New(dErrors.CodeInternal, msg)
		}
		return err
	}

	return dErrors.Wrap(err, dErrors.CodeInternal, msg)
}
