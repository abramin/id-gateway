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

type TokenType string

const (
	TokenTypeAccess  TokenType = "access_token"
	TokenTypeRefresh TokenType = "refresh_token"
)

type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusInactive UserStatus = "inactive"
)

type ClientStatus string

const (
	ClientStatusActive   ClientStatus = "active"
	ClientStatusInactive ClientStatus = "inactive"
)

type TenantStatus string

const (
	TenantStatusActive   TenantStatus = "active"
	TenantStatusInactive TenantStatus = "inactive"
)
