package store

import (
	"context"
	"time"

	"id-gateway/internal/consent/models"
)

type Store interface {
	Save(ctx context.Context, consent *models.ConsentRecord) error
	FindByUserAndPurpose(ctx context.Context, userID string, purpose models.ConsentPurpose) (*models.ConsentRecord, error)
	ListByUser(ctx context.Context, userID string) ([]*models.ConsentRecord, error)
	Update(ctx context.Context, consent *models.ConsentRecord) error
	RevokeByUserAndPurpose(ctx context.Context, userID string, purpose models.ConsentPurpose, revokedAt time.Time) error
	DeleteByUser(ctx context.Context, userID string) error
}
