package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	dErrors "credo/pkg/domain-errors"
)

type User struct {
	ID        uuid.UUID  `json:"id"`
	TenantID  uuid.UUID  `json:"tenant_id"`
	Email     string     `json:"email"`
	FirstName string     `json:"first_name"`
	LastName  string     `json:"last_name"`
	Verified  bool       `json:"verified"`
	Status    UserStatus `json:"status"` // "active", "inactive"
}

type Session struct {
	ID             uuid.UUID `json:"id"`
	UserID         uuid.UUID `json:"user_id"`
	ClientID       uuid.UUID `json:"client_id"`
	TenantID       uuid.UUID `json:"tenant_id"`
	RequestedScope []string  `json:"requested_scope"`
	Status         string    `json:"status"` // "active", "revoked", "pending_consent"

	// Refresh lifecycle
	LastRefreshedAt    *time.Time `json:"last_refreshed_at,omitempty"` // last refresh action timestamp
	LastAccessTokenJTI string     `json:"-"`                           // latest issued access token JTI for revocation

	// Device binding for security - See DEVICE_BINDING.md for full security model
	DeviceID              string `json:"device_id,omitempty"`               // Primary: UUID from cookie (hard requirement)
	DeviceFingerprintHash string `json:"device_fingerprint_hash,omitempty"` // Secondary: SHA-256(browser|os|platform) - no IP

	// Device display metadata (optional, for session management UI)
	DeviceDisplayName   string `json:"device_display_name,omitempty"`  // e.g., "Chrome on macOS"
	ApproximateLocation string `json:"approximate_location,omitempty"` // e.g., "San Francisco, US"

	// Lifecycle timestamps
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`   // Session expiry (30+ days)
	LastSeenAt time.Time  `json:"last_seen_at"` // Last activity timestamp
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

type AuthorizationCodeRecord struct {
	ID          uuid.UUID `json:"id"`           // Unique identifier
	Code        string    `json:"code"`         // Format: "authz_<random>"
	SessionID   uuid.UUID `json:"session_id"`   // Links to parent Session
	RedirectURI string    `json:"redirect_uri"` // Stored for validation at token exchange
	ExpiresAt   time.Time `json:"expires_at"`   // 10 minutes from creation
	Used        bool      `json:"used"`         // Prevent replay attacks
	CreatedAt   time.Time `json:"created_at"`
}

// RefreshTokenRecord represents a long-lived token for access token renewal.
// Lifetime: 30 days (configurable)
type RefreshTokenRecord struct {
	ID              uuid.UUID  `json:"id"`         // Unique identifier
	Token           string     `json:"token"`      // Format: "ref_<uuid>"
	SessionID       uuid.UUID  `json:"session_id"` // Links to parent Session
	ExpiresAt       time.Time  `json:"expires_at"` // 30 days from creation
	Used            bool       `json:"used"`       // For rotation detection
	LastRefreshedAt *time.Time `json:"last_refreshed_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// NewUser creates a User with domain invariant checks.
func NewUser(id uuid.UUID, tenantID uuid.UUID, email, firstName, lastName string, verified bool) (*User, error) {
	if id == uuid.Nil {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "user ID cannot be nil")
	}
	if tenantID == uuid.Nil {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "user tenant ID cannot be nil")
	}
	if email == "" {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "user email cannot be empty")
	}
	return &User{
		ID:        id,
		TenantID:  tenantID,
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		Verified:  verified,
		Status:    UserStatusActive,
	}, nil
}

// NewSession creates a Session with domain invariant checks.
func NewSession(id, userID uuid.UUID, clientID uuid.UUID, tenantID uuid.UUID, scopes []string, status string, createdAt, expiresAt, lastSeenAt time.Time) (*Session, error) {
	if id == uuid.Nil {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "session ID cannot be nil")
	}
	if userID == uuid.Nil {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "user ID cannot be nil")
	}
	if clientID == uuid.Nil {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "client ID cannot be empty")
	}
	if tenantID == uuid.Nil {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "tenant ID cannot be nil")
	}
	if len(scopes) == 0 {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "scopes cannot be empty")
	}
	if status == "" {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "status cannot be empty")
	}
	if expiresAt.Before(createdAt) {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "session expiry must be after creation")
	}
	return &Session{
		ID:             id,
		UserID:         userID,
		ClientID:       clientID,
		TenantID:       tenantID,
		RequestedScope: scopes,
		Status:         status,
		CreatedAt:      createdAt,
		ExpiresAt:      expiresAt,
		LastSeenAt:     lastSeenAt,
	}, nil
}

// NewAuthorizationCode creates an AuthorizationCodeRecord with domain invariant checks.
func NewAuthorizationCode(code string, sessionID uuid.UUID, redirectURI string, createdAt, expiresAt time.Time) (*AuthorizationCodeRecord, error) {
	if code == "" {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "authorization code cannot be empty")
	}
	if sessionID == uuid.Nil {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "session ID cannot be nil")
	}
	if redirectURI == "" {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "redirect URI cannot be empty")
	}
	if expiresAt.Before(createdAt) {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "authorization code expiry must be after creation")
	}
	if expiresAt.Before(time.Now()) {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, fmt.Sprintf("authorization code already expired at %v", expiresAt))
	}
	return &AuthorizationCodeRecord{
		ID:          uuid.New(),
		Code:        code,
		SessionID:   sessionID,
		RedirectURI: redirectURI,
		ExpiresAt:   expiresAt,
		Used:        false,
		CreatedAt:   createdAt,
	}, nil
}

// NewRefreshToken creates a RefreshTokenRecord with domain invariant checks.
func NewRefreshToken(token string, sessionID uuid.UUID, createdAt, expiresAt time.Time) (*RefreshTokenRecord, error) {
	if token == "" {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "refresh token cannot be empty")
	}
	if sessionID == uuid.Nil {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "session ID cannot be nil")
	}
	if expiresAt.Before(createdAt) {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "refresh token expiry must be after creation")
	}
	if expiresAt.Before(time.Now()) {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, fmt.Sprintf("refresh token already expired at %v", expiresAt))
	}
	return &RefreshTokenRecord{
		ID:        uuid.New(),
		Token:     token,
		SessionID: sessionID,
		ExpiresAt: expiresAt,
		Used:      false,
		CreatedAt: createdAt,
	}, nil
}
