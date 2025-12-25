package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
)

// This file contains pure domain models for authentication: entities
// that should not depend on transport or HTTP-specific concerns.

type User struct {
	ID        id.UserID   `json:"id"`
	TenantID  id.TenantID `json:"tenant_id"`
	Email     string      `json:"email"`
	FirstName string      `json:"first_name"`
	LastName  string      `json:"last_name"`
	Verified  bool        `json:"verified"`
	Status    UserStatus  `json:"status"`
}

type Session struct {
	ID             id.SessionID  `json:"id"`
	UserID         id.UserID     `json:"user_id"`
	ClientID       id.ClientID   `json:"client_id"`
	TenantID       id.TenantID   `json:"tenant_id"`
	RequestedScope []string      `json:"requested_scope"`
	Status         SessionStatus `json:"status"`

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

func (s *Session) IsActive() bool {
	return s.Status == SessionStatusActive
}

func (s *Session) IsPendingConsent() bool {
	return s.Status == SessionStatusPendingConsent
}

func (s *Session) IsRevoked() bool {
	return s.Status == SessionStatusRevoked
}

func (s *Session) Activate() {
	if s.IsPendingConsent() {
		s.Status = SessionStatusActive
	}
}

// GetDeviceBinding returns the device binding information as a value object.
func (s *Session) GetDeviceBinding() DeviceBinding {
	return DeviceBinding{
		DeviceID:            s.DeviceID,
		FingerprintHash:     s.DeviceFingerprintHash,
		DisplayName:         s.DeviceDisplayName,
		ApproximateLocation: s.ApproximateLocation,
	}
}

// SetDeviceBinding updates all device binding fields from a DeviceBinding value object.
func (s *Session) SetDeviceBinding(binding DeviceBinding) {
	s.DeviceID = binding.DeviceID
	s.DeviceFingerprintHash = binding.FingerprintHash
	s.DeviceDisplayName = binding.DisplayName
	s.ApproximateLocation = binding.ApproximateLocation
}

// AuthorizationCodeRecord is a child aggregate of Session.
// Lifecycle: Short-lived (10 minutes), single-use.
// Invariants:
//   - Code cannot be empty
//   - RedirectURI must match at token exchange
//   - Used flag prevents replay attacks (must be set atomically with session activation)
//   - Parent Session must exist and be in pending_consent state for exchange
type AuthorizationCodeRecord struct {
	ID          uuid.UUID    `json:"id"`           // Unique identifier
	Code        string       `json:"code"`         // Format: "authz_<random>"
	SessionID   id.SessionID `json:"session_id"`   // Links to parent Session aggregate
	RedirectURI string       `json:"redirect_uri"` // Stored for validation at token exchange
	ExpiresAt   time.Time    `json:"expires_at"`   // 10 minutes from creation
	Used        bool         `json:"used"`         // Prevent replay attacks
	CreatedAt   time.Time    `json:"created_at"`
}

// IsValid returns true if the authorization code can be exchanged for tokens.
// A code is valid if it has not been used and has not expired.
func (a *AuthorizationCodeRecord) IsValid(now time.Time) bool {
	return !a.Used && a.ExpiresAt.After(now)
}

// IsExpired returns true if the authorization code has expired.
func (a *AuthorizationCodeRecord) IsExpired(now time.Time) bool {
	return now.After(a.ExpiresAt)
}

// RefreshTokenRecord is a child aggregate of Session.
// Lifecycle: Long-lived (30 days), supports rotation.
// Invariants:
//   - Token cannot be empty
//   - Used flag marks rotation (old token invalidated when new one issued)
//   - Parent Session must be active for refresh to succeed
//   - Replay of used token indicates potential token theft
type RefreshTokenRecord struct {
	ID              uuid.UUID    `json:"id"`         // Unique identifier
	Token           string       `json:"token"`      // Format: "ref_<uuid>"
	SessionID       id.SessionID `json:"session_id"` // Links to parent Session aggregate
	ExpiresAt       time.Time    `json:"expires_at"` // 30 days from creation
	Used            bool         `json:"used"`       // For rotation detection
	LastRefreshedAt *time.Time   `json:"last_refreshed_at,omitempty"`
	CreatedAt       time.Time    `json:"created_at"`
}

// IsValid returns true if the refresh token can be used to obtain new tokens.
// A token is valid if it has not been used (rotated) and has not expired.
func (r *RefreshTokenRecord) IsValid(now time.Time) bool {
	return !r.Used && r.ExpiresAt.After(now)
}

// IsExpired returns true if the refresh token has expired.
func (r *RefreshTokenRecord) IsExpired(now time.Time) bool {
	return now.After(r.ExpiresAt)
}

func (u *User) IsActive() bool {
	return u.Status == UserStatusActive
}

func NewUser(id id.UserID, tenantID id.TenantID, email, firstName, lastName string, verified bool) (*User, error) {
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

func NewSession(id id.SessionID, userID id.UserID, clientID id.ClientID, tenantID id.TenantID, scopes []string, status SessionStatus, createdAt time.Time, expiresAt time.Time, lastSeenAt time.Time) (*Session, error) {
	if len(scopes) == 0 {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "scopes cannot be empty")
	}
	if !status.IsValid() {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, fmt.Sprintf("invalid session status: %s", status))
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

func NewAuthorizationCode(code string, sessionID id.SessionID, redirectURI string, createdAt time.Time, expiresAt time.Time) (*AuthorizationCodeRecord, error) {
	if code == "" {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "authorization code cannot be empty")
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

func NewRefreshToken(token string, sessionID id.SessionID, createdAt time.Time, expiresAt time.Time) (*RefreshTokenRecord, error) {
	if token == "" {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "refresh token cannot be empty")
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
