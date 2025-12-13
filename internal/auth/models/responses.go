package models

import "time"

// AuthorizationResult represents the response to a successful authorization request,
// containing the authorization code and redirect URI.
type AuthorizationResult struct {
	Code        string `json:"code" validate:"required"`
	RedirectURI string `json:"redirect_uri" validate:"required,url,max=2048"`
	DeviceID    string `json:"-"`
}

// TokenResult represents the response to a successful token exchange,
// containing access token, ID token, refresh token, and expiration.
type TokenResult struct {
	AccessToken  string        `json:"access_token" validate:"required"`
	IDToken      string        `json:"id_token" validate:"required"`
	RefreshToken string        `json:"refresh_token" validate:"required"`
	ExpiresIn    time.Duration `json:"expires_in" validate:"required"`
	TokenType    string        `json:"token_type" validate:"required,eq=Bearer"`
}

// UserInfoResult represents the response to a userinfo request,
// containing standardized OpenID Connect claims about the authenticated user.
type UserInfoResult struct {
	Sub           string `json:"sub" validate:"required"`                 // Subject - Identifier for the End-User at the Issuer.
	Email         string `json:"email" validate:"required,email,max=255"` // End-User's preferred e-mail address.
	EmailVerified bool   `json:"email_verified" validate:"required"`      // True if the End-User's e-mail address has been verified.
	GivenName     string `json:"given_name" validate:"max=100"`           // End-User's given name(s) or first name(s).
	FamilyName    string `json:"family_name" validate:"max=100"`          // End-User's family name(s) or last name(s).
	Name          string `json:"name" validate:"max=100"`                 // End-User's full name.
}

// SessionSummary represents a summary of an active session for display to the user.
type SessionSummary struct {
	SessionID    string    `json:"session_id"`
	Device       string    `json:"device"`
	IPAddress    string    `json:"ip_address,omitempty"`
	Location     string    `json:"location,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	LastActivity time.Time `json:"last_activity"`
	IsCurrent    bool      `json:"is_current"`
}

// SessionsResult represents the response to a list sessions request,
// containing a collection of active sessions for the authenticated user.
type SessionsResult struct {
	Sessions []SessionSummary `json:"sessions"`
}
