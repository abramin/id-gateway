package models

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
type Grant string

const (
	GrantAuthorizationCode Grant = "authorization_code"
	GrantRefreshToken      Grant = "refresh_token"
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

// ClientStatus represents whether a client is active or inactive.
type ClientStatus string

const (
	ClientStatusActive   ClientStatus = "active"
	ClientStatusInactive ClientStatus = "inactive"
)

// TenantStatus represents whether a tenant is active or inactive.
type TenantStatus string

const (
	TenantStatusActive   TenantStatus = "active"
	TenantStatusInactive TenantStatus = "inactive"
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
