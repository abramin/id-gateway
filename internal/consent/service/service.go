package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"id-gateway/internal/audit"
	"id-gateway/internal/consent/models"
	pkgerrors "id-gateway/pkg/domain-errors"
)

type Store interface {
	Save(ctx context.Context, consent *models.ConsentRecord) error
	FindByUserAndPurpose(ctx context.Context, userID string, purpose models.ConsentPurpose) (*models.ConsentRecord, error)
	ListByUser(ctx context.Context, userID string) ([]*models.ConsentRecord, error)
	Update(ctx context.Context, consent *models.ConsentRecord) error
	RevokeByUserAndPurpose(ctx context.Context, userID string, purpose models.ConsentPurpose, revokedAt time.Time) error
	DeleteByUser(ctx context.Context, userID string) error
}

// Service persists consent decisions and enforces lifecycle rules per PRD-002.
type Service struct {
	store   Store
	auditor *audit.Publisher
	now     func() time.Time
	ttl     time.Duration
}

type Option func(*Service)

func WithAuditor(a *audit.Publisher) Option {
	return func(s *Service) {
		s.auditor = a
	}
}

func WithNow(now func() time.Time) Option {
	return func(s *Service) {
		s.now = now
	}
}

func WithTTL(ttl time.Duration) Option {
	return func(s *Service) {
		s.ttl = ttl
	}
}

func NewService(store Store, opts ...Option) *Service {
	svc := &Service{
		store: store,
		now:   time.Now,
		ttl:   365 * 24 * time.Hour,
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

func (s *Service) Grant(ctx context.Context, userID string, purposes []models.ConsentPurpose) ([]*models.ConsentRecord, error) {
	if userID == "" {
		return nil, pkgerrors.New(pkgerrors.CodeUnauthorized, "missing user context")
	}
	if len(purposes) == 0 {
		return nil, pkgerrors.New(pkgerrors.CodeBadRequest, "purposes array must not be empty")
	}
	for _, purpose := range purposes {
		if !purpose.IsValid() {
			return nil, pkgerrors.New(pkgerrors.CodeBadRequest, fmt.Sprintf("invalid purpose: %s", purpose))
		}
	}

	var granted []*models.ConsentRecord
	for _, purpose := range purposes {
		record, err := s.upsertGrant(ctx, userID, purpose)
		if err != nil {
			return nil, err
		}
		granted = append(granted, record)
	}
	return granted, nil
}

func (s *Service) upsertGrant(ctx context.Context, userID string, purpose models.ConsentPurpose) (*models.ConsentRecord, error) {
	now := s.now()
	expiry := now.Add(s.ttl)
	existing, err := s.store.FindByUserAndPurpose(ctx, userID, purpose)
	if err != nil {
		return nil, pkgerrors.Wrap(pkgerrors.CodeInternal, "failed to read consent", err)
	}

	if existing != nil && existing.IsActive(now) {
		existing.GrantedAt = now
		existing.ExpiresAt = &expiry
		existing.RevokedAt = nil
		if err := s.store.Update(ctx, existing); err != nil {
			return nil, pkgerrors.Wrap(pkgerrors.CodeInternal, "failed to renew consent", err)
		}
		s.emitAudit(ctx, userID, purpose, "granted", "consent_granted")
		return existing, nil
	}

	record := &models.ConsentRecord{
		ID:        fmt.Sprintf("consent_%s", uuid.New().String()),
		UserID:    userID,
		Purpose:   purpose,
		GrantedAt: now,
		ExpiresAt: &expiry,
	}
	if err := s.store.Save(ctx, record); err != nil {
		return nil, pkgerrors.Wrap(pkgerrors.CodeInternal, "failed to save consent", err)
	}
	s.emitAudit(ctx, userID, purpose, "granted", "consent_granted")
	return record, nil
}

func (s *Service) Revoke(ctx context.Context, userID string, purpose models.ConsentPurpose) error {
	if userID == "" {
		return pkgerrors.New(pkgerrors.CodeUnauthorized, "missing user context")
	}
	if !purpose.IsValid() {
		return pkgerrors.New(pkgerrors.CodeBadRequest, fmt.Sprintf("invalid purpose: %s", purpose))
	}

	now := s.now()
	record, err := s.store.FindByUserAndPurpose(ctx, userID, purpose)
	if err != nil {
		return pkgerrors.Wrap(pkgerrors.CodeInternal, "failed to read consent", err)
	}
	if record == nil || record.RevokedAt != nil {
		return nil
	}
	if record.ExpiresAt != nil && record.ExpiresAt.Before(now) {
		return nil
	}
	if err := s.store.RevokeByUserAndPurpose(ctx, userID, purpose, now); err != nil {
		return pkgerrors.Wrap(pkgerrors.CodeInternal, "failed to revoke consent", err)
	}
	s.emitAudit(ctx, userID, purpose, "revoked", "consent_revoked")
	return nil
}

func (s *Service) List(ctx context.Context, userID string) ([]*models.ConsentRecord, error) {
	if userID == "" {
		return nil, pkgerrors.New(pkgerrors.CodeUnauthorized, "missing user context")
	}
	consents, err := s.store.ListByUser(ctx, userID)
	if err != nil {
		return nil, pkgerrors.Wrap(pkgerrors.CodeInternal, "failed to list consents", err)
	}
	return consents, nil
}

func (s *Service) Require(ctx context.Context, userID string, purpose models.ConsentPurpose) error {
	if userID == "" {
		return pkgerrors.New(pkgerrors.CodeUnauthorized, "missing user context")
	}
	if !purpose.IsValid() {
		return pkgerrors.New(pkgerrors.CodeBadRequest, fmt.Sprintf("invalid purpose: %s", purpose))
	}

	now := s.now()
	record, err := s.store.FindByUserAndPurpose(ctx, userID, purpose)
	if err != nil {
		return pkgerrors.Wrap(pkgerrors.CodeInternal, "failed to read consent", err)
	}
	if record == nil {
		s.emitAudit(ctx, userID, purpose, "denied", "consent_check_failed")
		return pkgerrors.New(pkgerrors.CodeMissingConsent, "consent not granted for required purpose")
	}
	if record.RevokedAt != nil {
		s.emitAudit(ctx, userID, purpose, "denied", "consent_check_failed")
		return pkgerrors.New(pkgerrors.CodeInvalidConsent, "consent revoked")
	}
	if record.ExpiresAt != nil && record.ExpiresAt.Before(now) {
		s.emitAudit(ctx, userID, purpose, "denied", "consent_check_failed")
		return pkgerrors.New(pkgerrors.CodeInvalidConsent, "consent expired")
	}
	s.emitAudit(ctx, userID, purpose, "granted", "consent_check_passed")
	return nil
}

func (s *Service) emitAudit(ctx context.Context, userID string, purpose models.ConsentPurpose, decision string, action string) {
	if s.auditor == nil {
		return
	}
	_ = s.auditor.Emit(ctx, audit.Event{
		UserID:    userID,
		Purpose:   string(purpose),
		Action:    action,
		Decision:  decision,
		Timestamp: s.now(),
	})
}
