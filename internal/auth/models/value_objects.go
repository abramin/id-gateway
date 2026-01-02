package models

import (
	"fmt"
	"strings"

	domain "credo/pkg/domain"
)

// SessionStatus represents the lifecycle state of an auth session.
type SessionStatus string

const (
	SessionStatusPendingConsent SessionStatus = "pending_consent"
	SessionStatusActive         SessionStatus = "active"
	SessionStatusRevoked        SessionStatus = "revoked"
)

func (s SessionStatus) IsValid() bool {
	return s == SessionStatusPendingConsent || s == SessionStatusActive || s == SessionStatusRevoked
}

func (s SessionStatus) String() string {
	return string(s)
}

// CanTransitionTo checks if a transition from the current status to the target is valid.
// Valid transitions:
// - pending_consent -> active (after consent granted)
// - active -> revoked (session revocation)
// - pending_consent -> revoked (session revocation before consent)
func (s SessionStatus) CanTransitionTo(target SessionStatus) bool {
	switch s {
	case SessionStatusPendingConsent:
		return target == SessionStatusActive || target == SessionStatusRevoked
	case SessionStatusActive:
		return target == SessionStatusRevoked
	case SessionStatusRevoked:
		return false // revoked is terminal
	default:
		return false
	}
}

// Grant represents supported OAuth grant types.
type Grant = domain.GrantType

const (
	GrantAuthorizationCode = domain.GrantTypeAuthorizationCode
	GrantRefreshToken      = domain.GrantTypeRefreshToken
)

// Scope represents a valid OAuth 2.0 / OIDC scope.
type Scope string

const (
	// ScopeOpenID is the required OIDC scope for authentication
	ScopeOpenID Scope = "openid"

	// ScopeProfile grants access to user profile information (name, given_name, family_name)
	ScopeProfile Scope = "profile"

	// ScopeEmail grants access to user email and email_verified claims
	ScopeEmail Scope = "email"
)

// TokenType represents supported token types in revocation flows.
type TokenType string

const (
	TokenTypeAccess  TokenType = "access_token"
	TokenTypeRefresh TokenType = "refresh_token"
)

// UserStatus represents whether a user is active or inactive.
type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusInactive UserStatus = "inactive"
)

// DeviceBinding consolidates device-related session data.
// This value object encapsulates the device identity and context signals
// used for session security and user display.
//
// Components:
//   - DeviceID: Primary identifier (UUID from cookie) - hard requirement for binding
//   - FingerprintHash: Secondary signal (SHA-256 of browser|os|platform) - drift detection
//   - DisplayName: Human-readable name for session management UI (e.g., "Chrome on macOS")
//   - ApproximateLocation: Optional geo context (e.g., "San Francisco, US")
type DeviceBinding struct {
	DeviceID            string `json:"device_id,omitempty"`
	FingerprintHash     string `json:"fingerprint_hash,omitempty"`
	DisplayName         string `json:"display_name,omitempty"`
	ApproximateLocation string `json:"approximate_location,omitempty"`
}

// IsEmpty returns true if no device binding information is present.
func (d DeviceBinding) IsEmpty() bool {
	return d.DeviceID == "" && d.FingerprintHash == "" && d.DisplayName == "" && d.ApproximateLocation == ""
}

// HasDeviceID returns true if a device ID is bound to this session.
func (d DeviceBinding) HasDeviceID() bool {
	return d.DeviceID != ""
}

// HasFingerprint returns true if a fingerprint hash is present.
func (d DeviceBinding) HasFingerprint() bool {
	return d.FingerprintHash != ""
}

// DisplayNameOrDefault returns the display name, or "Unknown device" if empty.
func (d DeviceBinding) DisplayNameOrDefault() string {
	if d.DisplayName == "" {
		return "Unknown device"
	}
	return d.DisplayName
}

// NewDeviceBinding creates a DeviceBinding with trimmed field values.
// At least one of deviceID or fingerprintHash should be provided for meaningful binding.
func NewDeviceBinding(deviceID, fingerprintHash, displayName, location string) DeviceBinding {
	return DeviceBinding{
		DeviceID:            strings.TrimSpace(deviceID),
		FingerprintHash:     strings.TrimSpace(fingerprintHash),
		DisplayName:         strings.TrimSpace(displayName),
		ApproximateLocation: strings.TrimSpace(location),
	}
}

// RevocationReason represents why a session/token was revoked.
// Tracked for audit, compliance, and analytics purposes.
type RevocationReason string

const (
	// RevocationReasonUserInitiated means user explicitly revoked the token.
	RevocationReasonUserInitiated RevocationReason = "user_initiated"

	// RevocationReasonExpired means the token expired naturally.
	RevocationReasonExpired RevocationReason = "expired"

	// RevocationReasonUserDeleted means admin deleted the user.
	RevocationReasonUserDeleted RevocationReason = "user_deleted"

	// RevocationReasonAdminRevoked means admin explicitly revoked the session.
	RevocationReasonAdminRevoked RevocationReason = "admin_revoked"

	// RevocationReasonSecurityEvent means revocation due to suspicious activity.
	RevocationReasonSecurityEvent RevocationReason = "security_event"

	// RevocationReasonReplayDetected means a replay attack was detected.
	RevocationReasonReplayDetected RevocationReason = "replay_detected"

	// RevocationReasonTokenRotation means old token was invalidated by rotation.
	RevocationReasonTokenRotation RevocationReason = "token_rotation"
)

var validRevocationReasons = map[RevocationReason]bool{
	RevocationReasonUserInitiated:  true,
	RevocationReasonExpired:        true,
	RevocationReasonUserDeleted:    true,
	RevocationReasonAdminRevoked:   true,
	RevocationReasonSecurityEvent:  true,
	RevocationReasonReplayDetected: true,
	RevocationReasonTokenRotation:  true,
}

// IsValid checks if the revocation reason is one of the supported enum values.
func (r RevocationReason) IsValid() bool {
	return validRevocationReasons[r]
}

// String returns the string representation of the revocation reason.
func (r RevocationReason) String() string {
	return string(r)
}

// ParseRevocationReason converts a string to RevocationReason.
// Returns error if the string is not a valid reason.
func ParseRevocationReason(s string) (RevocationReason, error) {
	r := RevocationReason(s)
	if !r.IsValid() {
		return "", fmt.Errorf("invalid revocation reason: %q", s)
	}
	return r, nil
}
