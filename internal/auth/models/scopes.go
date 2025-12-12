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

// ValidScopes returns all valid scope constants
func ValidScopes() []Scope {
	return []Scope{
		ScopeOpenID,
		ScopeProfile,
		ScopeEmail,
	}
}

// IsValid checks if a scope string is valid
func IsValid(scope string) bool {
	for _, valid := range ValidScopes() {
		if valid.String() == scope {
			return true
		}
	}
	return false
}

// ToStrings converts a slice of Scope to []string
func ToStrings(scopes []Scope) []string {
	result := make([]string, len(scopes))
	for i, s := range scopes {
		result[i] = s.String()
	}
	return result
}

// FromStrings converts a slice of strings to []Scope
func FromStrings(scopes []string) []Scope {
	result := make([]Scope, 0, len(scopes))
	for _, s := range scopes {
		result = append(result, Scope(s))
	}
	return result
}
