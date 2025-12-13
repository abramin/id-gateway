package models

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

// String returns the string representation of a Scope
func (s Scope) String() string {
	return string(s)
}
