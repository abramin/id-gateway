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

// Session models an authorization session.
type Session struct {
	ID             uuid.UUID `json:"id" validate:"required,uuid"`
	UserID         uuid.UUID `json:"user_id" validate:"required,uuid"`
	RequestedScope []string  `json:"requested_scope" validate:"dive,required"`
	Status         string    `json:"status" validate:"required"`
	CreatedAt      time.Time `json:"created_at" validate:"required"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type AuthorizationRequest struct {
	Email       string   `json:"email" validate:"required,email,max=255"`
	ClientID    string   `json:"client_id" validate:"required,min=3,max=100"`
	Scopes      []string `json:"scopes" validate:"required,min=1,dive,notblank"`
	RedirectURI string   `json:"redirect_uri" validate:"required,url,max=2048"`
	State       string   `json:"state" validate:"max=500"`
}

type AuthorizationResult struct {
	SessionID   uuid.UUID `json:"session_id" validate:"required,uuid"`
	RedirectURI string    `json:"redirect_uri" validate:"required,url,max=2048"`
}

type ConsentRequest struct {
	SessionID uuid.UUID `json:"session_id" validate:"required,uuid"`
	Approved  bool      `json:"approved" validate:"required"`
}

type ConsentResult struct {
	SessionID uuid.UUID `json:"session_id" validate:"required,uuid"`
	Approved  bool      `json:"approved" validate:"required"`
}

type TokenRequest struct {
	SessionID uuid.UUID `json:"session_id" validate:"required,uuid"`
	Code      string    `json:"code" validate:"required"`
}

type TokenResult struct {
	AccessToken string `json:"access_token" validate:"required"`
	IDToken     string `json:"id_token" validate:"required"`
	ExpiresIn   int    `json:"expires_in" validate:"required"`
}

var ErrUserNotFound = &ModelError{Code: "user_not_found", Message: "user not found"}

type ModelError struct {
	Code    string
	Message string
}

func (e *ModelError) Error() string {
	return e.Message
}
