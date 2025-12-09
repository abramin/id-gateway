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
	Save(ctx context.Context, consent *models.Record) error
	FindByUserAndPurpose(ctx context.Context, userID string, purpose models.Purpose) (*models.Record, error)
	ListByUser(ctx context.Context, userID string) ([]*models.Record, error)
	Update(ctx context.Context, consent *models.Record) error
	RevokeByUserAndPurpose(ctx context.Context, userID string, purpose models.Purpose, revokedAt time.Time) (*models.Record, error)
	DeleteByUser(ctx context.Context, userID string) error
}

// Service persists consent decisions and enforces lifecycle rules per PRD-002.
type Service struct {
	store   Store
	auditor *audit.Publisher
	ttl     time.Duration
}

func NewService(store Store, auditor *audit.Publisher) *Service {
	svc := &Service{
		store: store,
		ttl:   365 * 24 * time.Hour, // TODO: add to config
	}
	return svc
}

func (s *Service) Grant(ctx context.Context, userID string, purposes []models.Purpose) ([]*models.Record, error) {
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

	var granted []*models.Record
	for _, purpose := range purposes {
		record, err := s.upsertGrant(ctx, userID, purpose)
		if err != nil {
			return nil, err
		}
		granted = append(granted, record)
	}
	return granted, nil
}

func (s *Service) upsertGrant(ctx context.Context, userID string, purpose models.Purpose) (*models.Record, error) {
	now := time.Now()
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

	record := &models.Record{
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

func (s *Service) Revoke(ctx context.Context, userID string, purposes []models.Purpose) ([]*models.Record, error) {
	if userID == "" {
		return nil, pkgerrors.New(pkgerrors.CodeUnauthorized, "missing user context")
	}
	for _, purpose := range purposes {
		if !purpose.IsValid() {
			return nil, pkgerrors.New(pkgerrors.CodeBadRequest, fmt.Sprintf("invalid purpose: %s", purpose))
		}
	}

	var revoked []*models.Record
	for _, purpose := range purposes {
		record, err := s.store.FindByUserAndPurpose(ctx, userID, purpose)
		if err != nil {
			return nil, pkgerrors.Wrap(pkgerrors.CodeInternal, "failed to read consent", err)
		}
		if record == nil || record.RevokedAt != nil {
			continue
		}
		if record.ExpiresAt != nil && record.ExpiresAt.Before(time.Now()) {
			continue
		}
		_, err = s.store.RevokeByUserAndPurpose(ctx, userID, record.Purpose, time.Now())
		if err != nil {
			return nil, pkgerrors.Wrap(pkgerrors.CodeInternal, "failed to revoke consent", err)
		}
		s.emitAudit(ctx, userID, record.Purpose, "revoked", "consent_revoked")
		revoked = append(revoked, record)
	}
	return revoked, nil
}

func (s *Service) List(ctx context.Context, userID string, filter *models.RecordFilter) ([]*models.RecordWithStatus, error) {
	if userID == "" {
		return nil, pkgerrors.New(pkgerrors.CodeUnauthorized, "missing user context")
	}
	_, err := s.store.ListByUser(ctx, userID)
	if err != nil {
		return nil, pkgerrors.Wrap(pkgerrors.CodeInternal, "failed to list consents", err)
	}
	return nil, nil
}

func (s *Service) Require(ctx context.Context, userID string, purpose models.Purpose) error {
	if userID == "" {
		return pkgerrors.New(pkgerrors.CodeUnauthorized, "missing user context")
	}
	if !purpose.IsValid() {
		return pkgerrors.New(pkgerrors.CodeBadRequest, fmt.Sprintf("invalid purpose: %s", purpose))
	}

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
	if record.ExpiresAt != nil && record.ExpiresAt.Before(time.Now()) {
		s.emitAudit(ctx, userID, purpose, "denied", "consent_check_failed")
		return pkgerrors.New(pkgerrors.CodeInvalidConsent, "consent expired")
	}
	s.emitAudit(ctx, userID, purpose, "granted", "consent_check_passed")
	return nil
}

func (s *Service) emitAudit(ctx context.Context, userID string, purpose models.Purpose, decision string, action string) {
	if s.auditor == nil {
		return
	}
	_ = s.auditor.Emit(ctx, audit.Event{
		UserID:    userID,
		Purpose:   string(purpose),
		Action:    action,
		Decision:  decision,
		Timestamp: time.Now(),
	})
}
