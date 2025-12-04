package models

import "github.com/google/uuid"

// User captures the primary identity tracked by the gateway. Storage of the
// actual user record lives behind the UserStore interface.
type User struct {
	ID        uuid.UUID `json:"id"`
	Email     string
	FirstName string
	LastName  string
	Verified  bool
}

// Session models an authorization session.
type Session struct {
	ID             uuid.UUID
	UserID         uuid.UUID
	RequestedScope []string
	Status         string
}

type AuthorizationRequest struct {
	Email       string   `json:"email" validate:"required,email,max=255"`
	ClientID    string   `json:"client_id" validate:"required,min=3,max=100"`
	Scopes      []string `json:"scopes" validate:"dive,required"`
	RedirectURI string   `json:"redirect_uri" validate:"required,url,max=2048"`
	State       string   `json:"state" validate:"max=500"`
}

type AuthorizationResult struct {
	SessionID uuid.UUID
	UserID    uuid.UUID
}

type ConsentRequest struct {
	SessionID uuid.UUID
	Approved  bool
}

type ConsentResult struct {
	SessionID uuid.UUID
	Approved  bool
}

type TokenRequest struct {
	SessionID uuid.UUID
	Code      string
}

type TokenResult struct {
	AccessToken string
	IDToken     string
	ExpiresIn   int
}
