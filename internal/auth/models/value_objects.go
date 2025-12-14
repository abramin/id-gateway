package models

type SessionStatus string

const (
	SessionStatusPendingConsent SessionStatus = "pending_consent"
	SessionStatusActive         SessionStatus = "active"
	SessionStatusRevoked        SessionStatus = "revoked"
)

type Grant string

const (
	GrantAuthorizationCode Grant = "authorization_code"
	GrantRefreshToken      Grant = "refresh_token"
)

// Scope represents a valid OAuth 2.0 / OIDC scope
type Scope string

const (
	// ScopeOpenID is the required OIDC scope for authentication
	ScopeOpenID Scope = "openid"

	// ScopeProfile grants access to user profile information (name, given_name, family_name)
	ScopeProfile Scope = "profile"

	// ScopeEmail grants access to user email and email_verified claims
	ScopeEmail Scope = "email"
)
