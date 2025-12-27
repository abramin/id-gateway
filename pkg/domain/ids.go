// Package domain provides type-safe identifiers to prevent mixing up IDs at compile time.
package domain

import (
	"regexp"

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

// NationalID is a validated national identifier (6-20 uppercase alphanumeric characters).
// This is a domain primitive that enforces validity at parse time.
type NationalID struct {
	value string
}

// nationalIDPattern validates the national ID format: 6-20 uppercase alphanumeric characters.
var nationalIDPattern = regexp.MustCompile(`^[A-Z0-9]{6,20}$`)

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

// ParseNationalID validates and creates a NationalID from a string.
// The ID must be 6-20 uppercase alphanumeric characters.
func ParseNationalID(s string) (NationalID, error) {
	if s == "" {
		return NationalID{}, dErrors.New(dErrors.CodeInvalidInput, "national_id is required")
	}
	if !nationalIDPattern.MatchString(s) {
		return NationalID{}, dErrors.New(dErrors.CodeInvalidInput, "national_id has invalid format: must be 6-20 alphanumeric characters")
	}
	return NationalID{value: s}, nil
}

func (id UserID) String() string     { return uuid.UUID(id).String() }
func (id SessionID) String() string  { return uuid.UUID(id).String() }
func (id ClientID) String() string   { return uuid.UUID(id).String() }
func (id TenantID) String() string   { return uuid.UUID(id).String() }
func (id ConsentID) String() string  { return uuid.UUID(id).String() }
func (id APIKeyID) String() string   { return string(id) }
func (id NationalID) String() string { return id.value }

func (id UserID) IsNil() bool     { return uuid.UUID(id) == uuid.Nil }
func (id SessionID) IsNil() bool  { return uuid.UUID(id) == uuid.Nil }
func (id ClientID) IsNil() bool   { return uuid.UUID(id) == uuid.Nil }
func (id TenantID) IsNil() bool   { return uuid.UUID(id) == uuid.Nil }
func (id ConsentID) IsNil() bool  { return uuid.UUID(id) == uuid.Nil }
func (id APIKeyID) IsNil() bool   { return id == "" }
func (id NationalID) IsNil() bool { return id.value == "" }

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
