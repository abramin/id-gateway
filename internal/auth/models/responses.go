package models

import "time"

// AuthorizationResult represents the response to a successful authorization request,
// containing the authorization code and redirect URI.
type AuthorizationResult struct {
	Code        string `json:"code"`
	RedirectURI string `json:"redirect_uri"`
	DeviceID    string `json:"device_id,omitempty"`
}

// TokenResult represents the response to a successful token exchange,
// containing access token, ID token, refresh token, and expiration.
type TokenResult struct {
	AccessToken  string        `json:"access_token"`
	IDToken      string        `json:"id_token"`
	RefreshToken string        `json:"refresh_token"`
	ExpiresIn    time.Duration `json:"expires_in"`
	TokenType    string        `json:"token_type"`
}

// UserInfoResult represents the response to a userinfo request,
// containing standardized OpenID Connect claims about the authenticated user.
type UserInfoResult struct {
	Sub           string `json:"sub"`            // Subject - Identifier for the End-User at the Issuer.
	Email         string `json:"email"`          // End-User's preferred e-mail address.
	EmailVerified bool   `json:"email_verified"` // True if the End-User's e-mail address has been verified.
	GivenName     string `json:"given_name"`     // End-User's given name(s) or first name(s).
	FamilyName    string `json:"family_name"`    // End-User's family name(s) or last name(s).
	Name          string `json:"name"`           // End-User's full name.
}

// SessionSummary represents a summary of an active session for display to the user.
type SessionSummary struct {
	SessionID    string    `json:"session_id"`
	Device       string    `json:"device"`
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

type SessionRevocationResult struct {
	Revoked   bool   `json:"revoked"`
	SessionID string `json:"session_id"`
	Message   string `json:"message"`
}

type LogoutAllResult struct {
	RevokedCount int `json:"revoked_count"`
}
