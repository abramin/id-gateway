package models

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
)

// This file contains pure domain models for authentication: entities
// that should not depend on transport or HTTP-specific concerns.

const authorizationCodePrefix = "authz_"

// User represents an authenticated end-user in the auth domain.
// This is a pure domain entity - use UserInfoResult for JSON responses.
type User struct {
	ID        id.UserID
	TenantID  id.TenantID
	Email     string
	FirstName string
	LastName  string
	Verified  bool
	Status    UserStatus
}

// Session represents an authentication session and its lifecycle state.
// This is a pure domain entity - use SessionSummary for JSON responses.
type Session struct {
	ID             id.SessionID
	UserID         id.UserID
	ClientID       id.ClientID
	TenantID       id.TenantID
	RequestedScope []string
	Status         SessionStatus

	// Refresh lifecycle
	LastRefreshedAt    *time.Time // last refresh action timestamp
	LastAccessTokenJTI string     // latest issued access token JTI for revocation

	// Device binding for security - See docs/security/DEVICE_BINDING.md for full security model
	DeviceID              string // Primary: UUID from cookie (hard requirement)
	DeviceFingerprintHash string // Secondary: SHA-256(browser|os|platform) - no IP

	// Device display metadata (optional, for session management UI)
	DeviceDisplayName   string // e.g., "Chrome on macOS"
	ApproximateLocation string // e.g., "San Francisco, US"

	// Lifecycle timestamps
	CreatedAt  time.Time
	ExpiresAt  time.Time // Session expiry (30+ days)
	LastSeenAt time.Time // Last activity timestamp
	RevokedAt  *time.Time
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

// Activate transitions the session from pending_consent to active.
// Returns true if the transition occurred, false if the session was already active or revoked.
func (s *Session) Activate() bool {
	if s.IsPendingConsent() {
		s.Status = SessionStatusActive
		return true
	}
	return false
}

// CanAdvance returns true if the session is in a state that allows token operations.
// When allowPending is true, both active and pending_consent states are valid
// (used during code exchange). When false, only active state is valid (used during refresh).
func (s *Session) CanAdvance(allowPending bool) bool {
	if s.IsActive() {
		return true
	}
	return allowPending && s.IsPendingConsent()
}

// Revoke transitions the session to revoked state.
// Returns true if the transition occurred, false if already revoked.
// The revokedAt time is only updated if it's after any existing RevokedAt value.
func (s *Session) Revoke(at time.Time) bool {
	if s.IsRevoked() {
		return false
	}
	s.Status = SessionStatusRevoked
	if s.RevokedAt == nil || at.After(*s.RevokedAt) {
		s.RevokedAt = &at
	}
	return true
}

// RecordActivity updates the session's last seen time if the given time is after the current value.
// This is used to track when the session was last active.
func (s *Session) RecordActivity(at time.Time) {
	if at.After(s.LastSeenAt) {
		s.LastSeenAt = at
	}
}

// RecordRefresh updates the session's refresh timestamp and activity time.
// This is used when a refresh token is exchanged for new tokens.
func (s *Session) RecordRefresh(at time.Time) {
	if s.LastRefreshedAt == nil || at.After(*s.LastRefreshedAt) {
		s.LastRefreshedAt = &at
	}
	s.RecordActivity(at)
}

// ApplyTokenJTI records the JTI of the latest access token issued for this session.
func (s *Session) ApplyTokenJTI(jti string) {
	if jti != "" {
		s.LastAccessTokenJTI = jti
	}
}

// ApplyDeviceInfo updates device binding fields if the provided values are non-empty.
func (s *Session) ApplyDeviceInfo(deviceID, fingerprintHash string) {
	if deviceID != "" {
		s.DeviceID = deviceID
	}
	if fingerprintHash != "" {
		s.DeviceFingerprintHash = fingerprintHash
	}
}

// ValidateForAdvance checks if the session can be advanced (used for token operations).
// It verifies: client ID matches, session is not revoked, status allows advancement, and not expired.
// allowPending=true permits pending_consent status (for code exchange).
// Returns nil if valid, or an error describing the validation failure.
func (s *Session) ValidateForAdvance(clientID id.ClientID, at time.Time, allowPending bool) error {
	if s.ClientID != clientID {
		return dErrors.New(dErrors.CodeUnauthorized, "client_id mismatch")
	}
	if s.IsRevoked() {
		return dErrors.New(dErrors.CodeUnauthorized, "session has been revoked")
	}
	if !s.CanAdvance(allowPending) {
		return dErrors.New(dErrors.CodeUnauthorized, "session in invalid state")
	}
	if at.After(s.ExpiresAt) {
		return dErrors.New(dErrors.CodeUnauthorized, "session expired")
	}
	return nil
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
	ID          uuid.UUID    // Unique identifier
	Code        string       // Format: "authz_<random>" (prefix added at creation)
	SessionID   id.SessionID // Links to parent Session aggregate
	RedirectURI string       // Stored for validation at token exchange
	ExpiresAt   time.Time    // 10 minutes from creation
	Used        bool         // Prevent replay attacks
	CreatedAt   time.Time
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

// MarkUsed marks the authorization code as used for replay prevention.
// Returns true if the code was marked as used, false if it was already used.
func (a *AuthorizationCodeRecord) MarkUsed() bool {
	if a.Used {
		return false
	}
	a.Used = true
	return true
}

// ValidateForConsume checks if the authorization code can be consumed.
// It verifies: redirect URI matches, not expired, and not already used.
// Returns nil if valid, or an error describing the validation failure.
func (a *AuthorizationCodeRecord) ValidateForConsume(redirectURI string, now time.Time) error {
	if a.RedirectURI != redirectURI {
		return dErrors.New(dErrors.CodeBadRequest, "redirect_uri mismatch")
	}
	if a.IsExpired(now) {
		return dErrors.New(dErrors.CodeUnauthorized, "authorization code expired")
	}
	if a.Used {
		return dErrors.New(dErrors.CodeUnauthorized, "authorization code already used")
	}
	return nil
}

// RefreshTokenRecord is a child aggregate of Session.
// Lifecycle: Long-lived (30 days), supports rotation.
// Invariants:
//   - Token cannot be empty
//   - Used flag marks rotation (old token invalidated when new one issued)
//   - Parent Session must be active for refresh to succeed
//   - Replay of used token indicates potential token theft
type RefreshTokenRecord struct {
	ID              uuid.UUID    // Unique identifier
	Token           string       // Format: "ref_<uuid>"
	SessionID       id.SessionID // Links to parent Session aggregate
	ExpiresAt       time.Time    // 30 days from creation
	Used            bool         // For rotation detection
	LastRefreshedAt *time.Time
	CreatedAt       time.Time
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

// MarkUsed marks the refresh token as used for rotation tracking.
// Returns true if the token was marked as used, false if it was already used.
// Also records the time of the last refresh operation.
func (r *RefreshTokenRecord) MarkUsed(at time.Time) bool {
	if r.Used {
		return false
	}
	r.Used = true
	if r.LastRefreshedAt == nil || at.After(*r.LastRefreshedAt) {
		r.LastRefreshedAt = &at
	}
	return true
}

// ValidateForConsume checks if the refresh token can be consumed.
// It verifies: not expired and not already used.
// Returns nil if valid, or an error describing the validation failure.
func (r *RefreshTokenRecord) ValidateForConsume(now time.Time) error {
	if r.IsExpired(now) {
		return dErrors.New(dErrors.CodeUnauthorized, "refresh token expired")
	}
	if r.Used {
		return dErrors.New(dErrors.CodeUnauthorized, "refresh token already used")
	}
	return nil
}

func (u *User) IsActive() bool {
	return u.Status == UserStatusActive
}

// NewUser constructs a User and enforces basic invariants.
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

// NewSession constructs a Session and validates lifecycle invariants.
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

// NewAuthorizationCode constructs an AuthorizationCodeRecord with invariant checks.
func NewAuthorizationCode(code string, sessionID id.SessionID, redirectURI string, createdAt time.Time, expiresAt time.Time, now time.Time) (*AuthorizationCodeRecord, error) {
	if code == "" {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "authorization code cannot be empty")
	}
	code = strings.TrimPrefix(code, authorizationCodePrefix)
	if code == "" {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "authorization code cannot be empty")
	}
	if redirectURI == "" {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "redirect URI cannot be empty")
	}
	if expiresAt.Before(createdAt) {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "authorization code expiry must be after creation")
	}
	if expiresAt.Before(now) {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, fmt.Sprintf("authorization code already expired at %v", expiresAt))
	}
	return &AuthorizationCodeRecord{
		ID:          uuid.New(),
		Code:        authorizationCodePrefix + code,
		SessionID:   sessionID,
		RedirectURI: redirectURI,
		ExpiresAt:   expiresAt,
		Used:        false,
		CreatedAt:   createdAt,
	}, nil
}

// NewRefreshToken constructs a RefreshTokenRecord with invariant checks.
func NewRefreshToken(token string, sessionID id.SessionID, createdAt time.Time, expiresAt time.Time, now time.Time) (*RefreshTokenRecord, error) {
	if token == "" {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "refresh token cannot be empty")
	}
	if expiresAt.Before(createdAt) {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "refresh token expiry must be after creation")
	}
	if expiresAt.Before(now) {
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
