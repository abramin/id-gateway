package models

// AuthorizationRequest represents an OAuth authorization request from a client.
type AuthorizationRequest struct {
	Email       string   `json:"email" validate:"required,email,max=255"`
	ClientID    string   `json:"client_id" validate:"required,min=3,max=100"`
	Scopes      []string `json:"scopes" validate:"required,min=1,dive,notblank"`
	RedirectURI string   `json:"redirect_uri" validate:"required,url,max=2048"`
	State       string   `json:"state" validate:"max=500"`
}

// TokenRequest represents a request to exchange authorization code or refresh token for access tokens.
type TokenRequest struct {
	GrantType    string `json:"grant_type" validate:"required,oneof=authorization_code refresh_token"`
	ClientID     string `json:"client_id" validate:"required"`
	Code         string `json:"code,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty" validate:"omitempty,url"`
	RefreshToken string `json:"refresh_token,omitempty"`
}
