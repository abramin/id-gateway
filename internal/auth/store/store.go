package store

import (
	"context"

	"id-gateway/internal/auth/models"
	pkgerrors "id-gateway/pkg/http-errors"
)

var (
	// ErrNotFound keeps storage-specific 404s consistent across user/session
	// implementations.
	ErrNotFound = pkgerrors.New(pkgerrors.CodeNotFound, "record not found")
)

type UserStore interface {
	Save(ctx context.Context, user *models.User) error
	FindByID(ctx context.Context, id string) (*models.User, error)
	FindByEmail(ctx context.Context, email string) (*models.User, error)
}

type SessionStore interface {
	Save(ctx context.Context, session *models.Session) error
	FindByID(ctx context.Context, id string) (*models.Session, error)
	FindByCode(ctx context.Context, code string) (*models.Session, error)
}
