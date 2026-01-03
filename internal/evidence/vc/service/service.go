package service

import (
	"context"
	"errors"
	"log/slog"
	"time"

	registrycontracts "credo/contracts/registry"
	vccontracts "credo/contracts/vc"
	"credo/internal/evidence/vc/domain/credential"
	"credo/internal/evidence/vc/domain/shared"
	"credo/internal/evidence/vc/models"
	"credo/internal/evidence/vc/ports"
	"credo/internal/evidence/vc/store"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	"credo/pkg/platform/audit/publishers/ops"
	"credo/pkg/platform/sentinel"
	"credo/pkg/requestcontext"
)

// Option configures the VC service.
type Option func(*Service)

// Service issues and verifies verifiable credentials using registry evidence.
type Service struct {
	store       store.Store
	registry    ports.RegistryPort
	consentPort ports.ConsentPort
	auditor     *ops.Publisher
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

// WithAuditor configures an ops audit publisher for the service.
// VC events use fire-and-forget semantics via the ops publisher.
func WithAuditor(auditor *ops.Publisher) Option {
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

// Issue issues a new AgeOver18 credential after consent and registry verification.
// Side effects: registry lookup, store write, audit emission, and time retrieval.
func (s *Service) Issue(ctx context.Context, req models.IssueRequest) (*models.CredentialRecord, error) {
	if err := s.validateIssueRequest(req); err != nil {
		return nil, err
	}

	if err := s.requireVCIssuanceConsent(ctx, req.UserID); err != nil {
		return nil, err
	}

	now := requestcontext.Now(ctx)
	record, err := s.fetchCitizenRecord(ctx, req)
	if err != nil {
		return nil, err
	}

	vcModel, err := s.buildCredentialModel(req, record, now)
	if err != nil {
		return nil, err
	}

	if err := s.store.Save(ctx, vcModel); err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to store credential")
	}

	s.emitAudit(ctx, vcModel)

	return &vcModel, nil
}

func (s *Service) validateIssueRequest(req models.IssueRequest) error {
	if req.UserID.IsNil() {
		return dErrors.New(dErrors.CodeUnauthorized, "user ID required")
	}
	if req.Type != models.CredentialTypeAgeOver18 {
		return dErrors.New(dErrors.CodeBadRequest, "invalid credential type")
	}
	if req.NationalID.IsNil() {
		return dErrors.New(dErrors.CodeBadRequest, "national_id is required")
	}
	return nil
}

func (s *Service) fetchCitizenRecord(ctx context.Context, req models.IssueRequest) (*registrycontracts.CitizenRecord, error) {
	record, err := s.registry.Citizen(ctx, req.UserID, req.NationalID)
	if err != nil {
		return nil, sanitizeExternalError(err, "registry lookup failed")
	}
	if record == nil || !record.Valid {
		return nil, dErrors.New(dErrors.CodeBadRequest, "invalid citizen record")
	}
	return record, nil
}

func (s *Service) buildCredentialModel(req models.IssueRequest, record *registrycontracts.CitizenRecord, now time.Time) (models.CredentialRecord, error) {
	birthDate, err := time.Parse("2006-01-02", record.DateOfBirth)
	if err != nil {
		return models.CredentialRecord{}, dErrors.New(dErrors.CodeBadRequest, "invalid citizen record")
	}
	if !isOver18(birthDate, now) {
		return models.CredentialRecord{}, dErrors.New(dErrors.CodeBadRequest, "User does not meet age requirement")
	}

	claims := credential.NewAgeOver18Claims(true, models.VerifiedViaNationalRegistry)

	issuedAt, err := shared.NewIssuedAt(now)
	if err != nil {
		return models.CredentialRecord{}, dErrors.Wrap(err, dErrors.CodeInternal, "failed to create issuance timestamp")
	}

	cred, err := credential.New(
		models.NewCredentialID(),
		req.Type,
		req.UserID,
		models.IssuerCredo,
		issuedAt,
		claims,
	)
	if err != nil {
		return models.CredentialRecord{}, dErrors.Wrap(err, dErrors.CodeInternal, "failed to create credential")
	}

	if s.regulated {
		cred = cred.Minimized()
	}

	return credential.ToModel(cred), nil
}

// Verify validates an issued credential by ID and returns its stored content.
// Side effects: store read, audit emission, and domain error translation.
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

// FindCredentialPresence checks if a valid credential exists for a user and type.
// This is the decision-module-friendly entry point that returns minimal contract data.
// Returns CredentialPresence{Exists: false} if no credential found (not an error).
// Returns nil, error only for infrastructure failures.
func (s *Service) FindCredentialPresence(ctx context.Context, userID id.UserID, credType vccontracts.CredentialType) (*vccontracts.CredentialPresence, error) {
	internalType := models.CredentialType(credType)
	record, err := s.store.FindBySubjectAndType(ctx, userID, internalType)
	if err != nil {
		if errors.Is(err, sentinel.ErrNotFound) {
			return &vccontracts.CredentialPresence{Exists: false}, nil
		}
		return nil, err
	}
	return &vccontracts.CredentialPresence{
		Exists: true,
		Claims: map[string]interface{}(record.Claims),
	}, nil
}

const vcIssuancePurpose id.ConsentPurpose = id.ConsentPurposeVCIssuance

func (s *Service) requireVCIssuanceConsent(ctx context.Context, userID id.UserID) error {
	if s.consentPort == nil {
		return dErrors.New(dErrors.CodeInternal, "consent service unavailable")
	}
	if err := s.consentPort.RequireConsent(ctx, userID, vcIssuancePurpose); err != nil {
		return sanitizeExternalError(err, "consent check failed")
	}
	return nil
}

func (s *Service) emitAudit(ctx context.Context, credential models.CredentialRecord) {
	if s.auditor == nil {
		return
	}

	event := audit.OpsEvent{
		Action:    "vc_issued",
		Subject:   credential.Subject.String(),
		RequestID: requestcontext.RequestID(ctx),
	}

	// Fire-and-forget via ops publisher - no error handling needed
	s.auditor.Track(ctx, event)
}

func (s *Service) emitVerifyAudit(ctx context.Context, credential models.CredentialRecord) {
	if s.auditor == nil {
		return
	}

	event := audit.OpsEvent{
		Action:    "vc_verified",
		Subject:   credential.Subject.String(),
		RequestID: requestcontext.RequestID(ctx),
	}

	// Fire-and-forget via ops publisher - no error handling needed
	s.auditor.Track(ctx, event)
}

func isOver18(birthDate, now time.Time) bool {
	return id.IsOver18(birthDate, now)
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
