package models

import (
	"time"

	"github.com/google/uuid"
)

type contextKey string

const (
	ContextKeyUserAgent contextKey = "user_agent"
	ContextKeyIPAddress contextKey = "ip_address"
)

// User captures the primary identity tracked by the gateway. Storage of the
// actual user record lives behind the UserStore interface.
type User struct {
	ID        uuid.UUID `json:"id" validate:"required,uuid"`
	Email     string    `json:"email" validate:"required,email,max=255"`
	FirstName string    `json:"first_name" validate:"max=100"`
	LastName  string    `json:"last_name" validate:"max=100"`
	Verified  bool      `json:"verified" validate:"required"`
}

type Session struct {
	ID             uuid.UUID `json:"id"`
	UserID         uuid.UUID `json:"user_id"`
	ClientID       string    `json:"client_id"`
	RequestedScope []string  `json:"requested_scope"`
	Status         string    `json:"status"` // "active", "revoked", "pending_consent"

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

type AuthorizationRequest struct {
	Email       string   `json:"email" validate:"required,email,max=255"`
	ClientID    string   `json:"client_id" validate:"required,min=3,max=100"`
	Scopes      []string `json:"scopes" validate:"required,min=1,dive,notblank"`
	RedirectURI string   `json:"redirect_uri" validate:"required,url,max=2048"`
	State       string   `json:"state" validate:"max=500"`
}

type AuthorizationResult struct {
	Code        string `json:"code" validate:"required"`
	RedirectURI string `json:"redirect_uri" validate:"required,url,max=2048"`
	DeviceID    string `json:"-"`
}

type UserInfoResult struct {
	Sub           string `json:"sub" validate:"required"`                 // Subject - Identifier for the End-User at the Issuer.
	Email         string `json:"email" validate:"required,email,max=255"` // End-User's preferred e-mail address.
	EmailVerified bool   `json:"email_verified" validate:"required"`      // True if the End-User's e-mail address has been verified.
	GivenName     string `json:"given_name" validate:"max=100"`           // End-User's given name(s) or first name(s).
	FamilyName    string `json:"family_name" validate:"max=100"`          // End-User's family name(s) or last name(s).
	Name          string `json:"name" validate:"max=100"`                 // End-User's full name.
}

type TokenRequest struct {
	GrantType   string `json:"grant_type" validate:"required,oneof=authorization_code"`
	Code        string `json:"code" validate:"required"`
	RedirectURI string `json:"redirect_uri" validate:"required,url"`
	ClientID    string `json:"client_id" validate:"required"`
}

type TokenResult struct {
	AccessToken  string        `json:"access_token" validate:"required"`
	IDToken      string        `json:"id_token" validate:"required"`
	RefreshToken string        `json:"refresh_token" validate:"required"`
	ExpiresIn    time.Duration `json:"expires_in" validate:"required"`
	TokenType    string        `json:"token_type" validate:"required,eq=Bearer"`
}
