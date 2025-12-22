// Package domain provides type-safe identifiers to prevent mixing up IDs at compile time.
package domain

import (
	"github.com/google/uuid"

	dErrors "credo/pkg/domain-errors"
)

// Distinct ID types - compiler prevents passing UserID where TenantID is expected.
type (
	UserID    uuid.UUID
	SessionID uuid.UUID
	ClientID  uuid.UUID
	TenantID  uuid.UUID
	ConsentID uuid.UUID
)

// APIKeyID is a prefixed string identifier for API keys (e.g., "ak_xxxx").
type APIKeyID string

// Parse functions - use at trust boundaries (handlers, API inputs).

func ParseUserID(s string) (UserID, error) {
	id, err := parseUUID(s, "user ID")
	return UserID(id), err
}

func ParseSessionID(s string) (SessionID, error) {
	id, err := parseUUID(s, "session ID")
	return SessionID(id), err
}

func ParseClientID(s string) (ClientID, error) {
	id, err := parseUUID(s, "client ID")
	return ClientID(id), err
}

func ParseTenantID(s string) (TenantID, error) {
	id, err := parseUUID(s, "tenant ID")
	return TenantID(id), err
}

func ParseConsentID(s string) (ConsentID, error) {
	id, err := parseUUID(s, "consent ID")
	return ConsentID(id), err
}

func ParseAPIKeyID(s string) (APIKeyID, error) {
	if s == "" {
		return "", dErrors.New(dErrors.CodeInvalidInput, "API key ID cannot be empty")
	}
	return APIKeyID(s), nil
}

// String methods - for logging and debugging.

func (id UserID) String() string    { return uuid.UUID(id).String() }
func (id SessionID) String() string { return uuid.UUID(id).String() }
func (id ClientID) String() string  { return uuid.UUID(id).String() }
func (id TenantID) String() string  { return uuid.UUID(id).String() }
func (id ConsentID) String() string { return uuid.UUID(id).String() }
func (id APIKeyID) String() string  { return string(id) }

// IsNil checks - used for service-layer validation.

func (id UserID) IsNil() bool    { return uuid.UUID(id) == uuid.Nil }
func (id SessionID) IsNil() bool { return uuid.UUID(id) == uuid.Nil }
func (id ClientID) IsNil() bool  { return uuid.UUID(id) == uuid.Nil }
func (id TenantID) IsNil() bool  { return uuid.UUID(id) == uuid.Nil }
func (id ConsentID) IsNil() bool { return uuid.UUID(id) == uuid.Nil }
func (id APIKeyID) IsNil() bool  { return id == "" }

// parseUUID is the shared validation logic.
// Note: Nil UUIDs are allowed here. Use IsNil() at the service layer for
// business validation, which allows store lookups to return proper
// "not found" errors for consistency. See tenant/models/requests.go for rationale.
func parseUUID(s, label string) (uuid.UUID, error) {
	if s == "" {
		return uuid.Nil, dErrors.New(dErrors.CodeInvalidInput, label+" cannot be empty")
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, dErrors.New(dErrors.CodeInvalidInput, "invalid "+label+" format")
	}
	return id, nil
}
