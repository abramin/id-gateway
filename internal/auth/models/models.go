package models

import (
	"time"

	"github.com/google/uuid"
)

// User captures the primary identity tracked by the gateway. Storage of the
// actual user record lives behind the UserStore interface.
type User struct {
	ID        uuid.UUID `json:"id" validate:"required,uuid"`
	Email     string    `json:"email" validate:"required,email,max=255"`
	FirstName string    `json:"first_name" validate:"max=100"`
	LastName  string    `json:"last_name" validate:"max=100"`
	Verified  bool      `json:"verified" validate:"required"`
}

// Session models an OAuth 2.0 authorization session with authorization code flow support.
type Session struct {
	ID             uuid.UUID `json:"id" validate:"required,uuid"`
	UserID         uuid.UUID `json:"user_id" validate:"required,uuid"`
	Code           string    `json:"code" validate:"required"`             // OAuth 2.0 authorization code
	CodeExpiresAt  time.Time `json:"code_expires_at" validate:"required"`  // Authorization code expiry (10 minutes)
	CodeUsed       bool      `json:"code_used"`                            // Prevent replay attacks
	ClientID       string    `json:"client_id" validate:"required"`        // OAuth client identifier
	RedirectURI    string    `json:"redirect_uri" validate:"required,url"` // Stored for validation at token exchange
	RequestedScope []string  `json:"requested_scope" validate:"dive,required"`
	Status         string    `json:"status" validate:"required"`
	CreatedAt      time.Time `json:"created_at" validate:"required"`
	ExpiresAt      time.Time `json:"expires_at" validate:"required"`
}

type AuthorizationRequest struct {
	Email       string   `json:"email" validate:"required,email,max=255"`
	ClientID    string   `json:"client_id" validate:"required,min=3,max=100"`
	Scopes      []string `json:"scopes" validate:"required,min=1,dive,notblank"`
	RedirectURI string   `json:"redirect_uri" validate:"required,url,max=2048"`
	State       string   `json:"state" validate:"max=500"`
}

type AuthorizationResult struct {
	Code        string `json:"code" validate:"required"`
	RedirectURI string `json:"redirect_uri" validate:"required,url,max=2048"`
}

type UserInfoResult struct {
	Sub           string `json:"sub" validate:"required"`                 // Subject - Identifier for the End-User at the Issuer.
	Email         string `json:"email" validate:"required,email,max=255"` // End-User's preferred e-mail address.
	EmailVerified bool   `json:"email_verified" validate:"required"`      // True if the End-User's e-mail address has been verified.
	GivenName     string `json:"given_name" validate:"max=100"`           // End-User's given name(s) or first name(s).
	FamilyName    string `json:"family_name" validate:"max=100"`          // End-User's family name(s) or last name(s).
	Name          string `json:"name" validate:"max=100"`                 // End-User's full name.
}

type TokenRequest struct {
	GrantType   string `json:"grant_type" validate:"required,oneof=authorization_code"`
	Code        string `json:"code" validate:"required"`
	RedirectURI string `json:"redirect_uri" validate:"required,url"`
	ClientID    string `json:"client_id" validate:"required"`
}

type TokenResult struct {
	AccessToken string        `json:"access_token" validate:"required"`
	IDToken     string        `json:"id_token" validate:"required"`
	ExpiresIn   time.Duration `json:"expires_in" validate:"required"`
}
