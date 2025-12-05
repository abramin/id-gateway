package service

import (
	"context"
	"time"

	"id-gateway/internal/consent/models"
	pkgerrors "id-gateway/pkg/domain-errors"
)

type Store interface {
	Save(ctx context.Context, consent *models.ConsentRecord) error
	ListByUser(ctx context.Context, userID string) ([]*models.ConsentRecord, error)
	Revoke(ctx context.Context, userID string, purpose models.ConsentPurpose, revokedAt time.Time) error
}

// Service persists consent decisions and provides purpose-aware checks. It keeps
// orchestration out of handlers and domain logic thin.
type Service struct {
	store Store
}

func NewService(store Store) *Service {
	return &Service{store: store}
}

func (s *Service) Grant(ctx context.Context, userID string, purpose models.ConsentPurpose, ttl time.Duration) (*models.ConsentRecord, error) {
	now := time.Now()
	record := &models.ConsentRecord{
		UserID:    userID,
		Purpose:   purpose,
		GrantedAt: now,
		ExpiresAt: now.Add(ttl),
	}
	if err := s.store.Save(ctx, record); err != nil {
		return nil, err
	}
	return record, nil
}

// Require returns an error when consent is missing or expired.
func (s *Service) Require(ctx context.Context, userID string, purpose models.ConsentPurpose, now time.Time) error {
	consents, err := s.store.ListByUser(ctx, userID)
	if err != nil {
		return err
	}
	return models.EnsureConsent(consents, purpose, now)
}

func (s *Service) Revoke(ctx context.Context, userID string, purpose models.ConsentPurpose) error {
	now := time.Now()
	if err := s.store.Revoke(ctx, userID, purpose, now); err != nil {
		return pkgerrors.New(pkgerrors.CodeInvalidConsent, err.Error())
	}
	return nil
}

func (s *Service) List(ctx context.Context, userID string) ([]*models.ConsentRecord, error) {
	return s.store.ListByUser(ctx, userID)
}
