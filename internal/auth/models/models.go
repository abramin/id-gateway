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

	// Refresh lifecycle
	LastRefreshedAt *time.Time `json:"last_refreshed_at,omitempty"` // last refresh action timestamp

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
