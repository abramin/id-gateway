package store

import (
	"context"
	"time"

	"id-gateway/internal/consent/models"
)

type Store interface {
	Save(ctx context.Context, consent *models.Record) error
	FindByUserAndPurpose(ctx context.Context, userID string, purpose models.Purpose) (*models.Record, error)
	ListByUser(ctx context.Context, userID string) ([]*models.Record, error)
	Update(ctx context.Context, consent *models.Record) error
	RevokeByUserAndPurpose(ctx context.Context, userID string, purpose models.Purpose, revokedAt time.Time) (*models.Record, error)
	DeleteByUser(ctx context.Context, userID string) error
}
