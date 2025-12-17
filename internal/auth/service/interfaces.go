package service

import (
	"context"
	"time"

	"github.com/google/uuid"

	"credo/internal/audit"
	"credo/internal/auth/models"
	jwttoken "credo/internal/jwt_token"
	tenant "credo/internal/tenant/models"
)

// UserStore defines the persistence interface for user data.
// Error Contract: All Find methods return store.ErrNotFound when the entity doesn't exist.
type UserStore interface {
	Save(ctx context.Context, user *models.User) error
	FindByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	FindByEmail(ctx context.Context, email string) (*models.User, error)
	FindOrCreateByTenantAndEmail(ctx context.Context, tenantID uuid.UUID, email string, user *models.User) (*models.User, error)
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
	RevokeSessionIfActive(ctx context.Context, id uuid.UUID, now time.Time) error
	AdvanceLastSeen(ctx context.Context, id uuid.UUID, clientID string, at time.Time, accessTokenJTI string, activate bool, deviceID string, deviceFingerprintHash string) (*models.Session, error)
	AdvanceLastRefreshed(ctx context.Context, id uuid.UUID, clientID string, at time.Time, accessTokenJTI string, deviceID string, deviceFingerprintHash string) (*models.Session, error)
}

type AuthCodeStore interface {
	Create(ctx context.Context, authCode *models.AuthorizationCodeRecord) error
	FindByCode(ctx context.Context, code string) (*models.AuthorizationCodeRecord, error)
	MarkUsed(ctx context.Context, code string) error
	ConsumeAuthCode(ctx context.Context, code string, redirectURI string, now time.Time) (*models.AuthorizationCodeRecord, error)
	DeleteExpiredCodes(ctx context.Context) (int, error)
}

type RefreshTokenStore interface {
	Create(ctx context.Context, token *models.RefreshTokenRecord) error
	FindBySessionID(ctx context.Context, id uuid.UUID) (*models.RefreshTokenRecord, error)
	Find(ctx context.Context, tokenString string) (*models.RefreshTokenRecord, error)
	ConsumeRefreshToken(ctx context.Context, token string, now time.Time) (*models.RefreshTokenRecord, error)
	DeleteBySessionID(ctx context.Context, sessionID uuid.UUID) error
}

type TokenGenerator interface {
	GenerateAccessToken(userID uuid.UUID, sessionID uuid.UUID, clientID string, tenantID string, scopes []string) (string, error)
	GenerateAccessTokenWithJTI(userID uuid.UUID, sessionID uuid.UUID, clientID string, tenantID string, scopes []string) (string, string, error)
	GenerateIDToken(userID uuid.UUID, sessionID uuid.UUID, clientID string, tenantID string) (string, error)
	CreateRefreshToken() (string, error)
	// ParseTokenSkipClaimsValidation parses a JWT with signature verification but skips claims validation (e.g., expiration)
	// This is used for token revocation where we need to verify the signature but accept expired tokens
	ParseTokenSkipClaimsValidation(token string) (*jwttoken.AccessTokenClaims, error)
}

type AuditPublisher interface {
	Emit(ctx context.Context, base audit.Event) error
}

type ClientResolver interface {
	ResolveClient(ctx context.Context, clientID string) (*tenant.Client, *tenant.Tenant, error)
}
