package models

type TenantStatus string

const (
	TenantStatusActive   TenantStatus = "active"
	TenantStatusInactive TenantStatus = "inactive"
)

func (s TenantStatus) IsValid() bool {
	return s == TenantStatusActive || s == TenantStatusInactive
}

func (s TenantStatus) String() string {
	return string(s)
}

type ClientStatus string

const (
	ClientStatusActive   ClientStatus = "active"
	ClientStatusInactive ClientStatus = "inactive"
)

func (s ClientStatus) IsValid() bool {
	return s == ClientStatusActive || s == ClientStatusInactive
}

func (s ClientStatus) String() string {
	return string(s)
}

type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeRefreshToken      GrantType = "refresh_token"
	GrantTypeClientCredentials GrantType = "client_credentials"
)

func (g GrantType) IsValid() bool {
	switch g {
	case GrantTypeAuthorizationCode, GrantTypeRefreshToken, GrantTypeClientCredentials:
		return true
	}
	return false
}

func (g GrantType) String() string {
	return string(g)
}

// RequiresConfidentialClient returns true if this grant type can only be used
// by confidential clients (those with a client secret).
func (g GrantType) RequiresConfidentialClient() bool {
	return g == GrantTypeClientCredentials
}
