package service

import (
	"context"
	"time"

	"github.com/google/uuid"

	"credo/internal/audit"
	"credo/internal/auth/models"
)

// UserStore defines the persistence interface for user data.
// Error Contract: All Find methods return store.ErrNotFound when the entity doesn't exist.
type UserStore interface {
	Save(ctx context.Context, user *models.User) error
	FindByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	FindByEmail(ctx context.Context, email string) (*models.User, error)
	FindOrCreateByEmail(ctx context.Context, email string, user *models.User) (*models.User, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// SessionStore defines the persistence interface for session data.
// Error Contract: All Find methods return store.ErrNotFound when the entity doesn't exist.
type SessionStore interface {
	Create(ctx context.Context, session *models.Session) error
	FindByID(ctx context.Context, id uuid.UUID) (*models.Session, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.Session, error)
	UpdateSession(ctx context.Context, session *models.Session) error
	DeleteSessionsByUser(ctx context.Context, userID uuid.UUID) error
	RevokeSession(ctx context.Context, id uuid.UUID) error
}

type AuthCodeStore interface {
	Create(ctx context.Context, authCode *models.AuthorizationCodeRecord) error
	FindByCode(ctx context.Context, code string) (*models.AuthorizationCodeRecord, error)
	MarkUsed(ctx context.Context, code string) error
	Delete(ctx context.Context, code string) error
	DeleteExpiredCodes(ctx context.Context) (int, error)
}

type RefreshTokenStore interface {
	Create(ctx context.Context, token *models.RefreshTokenRecord) error
	FindBySessionID(ctx context.Context, id uuid.UUID) (*models.RefreshTokenRecord, error)
	Find(ctx context.Context, tokenString string) (*models.RefreshTokenRecord, error)
	Consume(ctx context.Context, token string, timestamp time.Time) error
	DeleteBySessionID(ctx context.Context, sessionID uuid.UUID) error
}

type TokenGenerator interface {
	GenerateAccessToken(userID uuid.UUID, sessionID uuid.UUID, clientID string) (string, error)
	GenerateIDToken(userID uuid.UUID, sessionID uuid.UUID, clientID string) (string, error)
	CreateRefreshToken() (string, error)
}

type AuditPublisher interface {
	Emit(ctx context.Context, base audit.Event) error
}
