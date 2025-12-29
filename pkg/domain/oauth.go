package domain

// GrantType represents an OAuth 2.0 grant type supported by the platform.
type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeRefreshToken      GrantType = "refresh_token"
	GrantTypeClientCredentials GrantType = "client_credentials"
)

// IsValid returns true if the grant type is a known valid value.
func (g GrantType) IsValid() bool {
	switch g {
	case GrantTypeAuthorizationCode, GrantTypeRefreshToken, GrantTypeClientCredentials:
		return true
	}
	return false
}

// String returns the string representation of the grant type.
func (g GrantType) String() string {
	return string(g)
}

// RequiresConfidentialClient returns true if this grant type can only be used
// by confidential clients (those with a client secret).
func (g GrantType) RequiresConfidentialClient() bool {
	return g == GrantTypeClientCredentials
}
