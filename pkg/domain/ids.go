// Package domain provides type-safe identifiers to prevent mixing up IDs at compile time.
package domain

import (
	"encoding/json"

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

// ParseUserID validates and converts a string to UserID.
// Use at trust boundaries (handlers, API inputs).
func ParseUserID(s string) (UserID, error) {
	id, err := parseUUID(s, "user ID")
	return UserID(id), err
}

// ParseSessionID validates and converts a string to SessionID.
func ParseSessionID(s string) (SessionID, error) {
	id, err := parseUUID(s, "session ID")
	return SessionID(id), err
}

// ParseClientID validates and converts a string to ClientID.
func ParseClientID(s string) (ClientID, error) {
	id, err := parseUUID(s, "client ID")
	return ClientID(id), err
}

// ParseTenantID validates and converts a string to TenantID.
func ParseTenantID(s string) (TenantID, error) {
	id, err := parseUUID(s, "tenant ID")
	return TenantID(id), err
}

// ParseConsentID validates and converts a string to ConsentID.
func ParseConsentID(s string) (ConsentID, error) {
	id, err := parseUUID(s, "consent ID")
	return ConsentID(id), err
}

func (id UserID) String() string {
	return uuid.UUID(id).String()
}

func (id SessionID) String() string {
	return uuid.UUID(id).String()
}

func (id ClientID) String() string {
	return uuid.UUID(id).String()
}

func (id TenantID) String() string {
	return uuid.UUID(id).String()
}

func (id ConsentID) String() string {
	return uuid.UUID(id).String()
}

// IsNil checks - used for service-layer validation.

func (id UserID) IsNil() bool    { return uuid.UUID(id) == uuid.Nil }
func (id SessionID) IsNil() bool { return uuid.UUID(id) == uuid.Nil }
func (id ClientID) IsNil() bool  { return uuid.UUID(id) == uuid.Nil }
func (id TenantID) IsNil() bool  { return uuid.UUID(id) == uuid.Nil }
func (id ConsentID) IsNil() bool { return uuid.UUID(id) == uuid.Nil }

// JSON marshaling - ensures IDs serialize as strings, not byte arrays.

func (id UserID) MarshalJSON() ([]byte, error) {
	return json.Marshal(uuid.UUID(id))
}

func (id *UserID) UnmarshalJSON(data []byte) error {
	var u uuid.UUID
	if err := json.Unmarshal(data, &u); err != nil {
		return err
	}
	*id = UserID(u)
	return nil
}

func (id SessionID) MarshalJSON() ([]byte, error) {
	return json.Marshal(uuid.UUID(id))
}

func (id *SessionID) UnmarshalJSON(data []byte) error {
	var u uuid.UUID
	if err := json.Unmarshal(data, &u); err != nil {
		return err
	}
	*id = SessionID(u)
	return nil
}

func (id ClientID) MarshalJSON() ([]byte, error) {
	return json.Marshal(uuid.UUID(id))
}

func (id *ClientID) UnmarshalJSON(data []byte) error {
	var u uuid.UUID
	if err := json.Unmarshal(data, &u); err != nil {
		return err
	}
	*id = ClientID(u)
	return nil
}

func (id TenantID) MarshalJSON() ([]byte, error) {
	return json.Marshal(uuid.UUID(id))
}

func (id *TenantID) UnmarshalJSON(data []byte) error {
	var u uuid.UUID
	if err := json.Unmarshal(data, &u); err != nil {
		return err
	}
	*id = TenantID(u)
	return nil
}

func (id ConsentID) MarshalJSON() ([]byte, error) {
	return json.Marshal(uuid.UUID(id))
}

func (id *ConsentID) UnmarshalJSON(data []byte) error {
	var u uuid.UUID
	if err := json.Unmarshal(data, &u); err != nil {
		return err
	}
	*id = ConsentID(u)
	return nil
}

// parseUUID is the shared validation logic.
func parseUUID(s, label string) (uuid.UUID, error) {
	if s == "" {
		return uuid.Nil, dErrors.New(dErrors.CodeInvalidInput, label+" cannot be empty")
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, dErrors.New(dErrors.CodeInvalidInput, "invalid "+label+" format")
	}
	if id == uuid.Nil {
		return uuid.Nil, dErrors.New(dErrors.CodeInvalidInput, label+" cannot be nil UUID")
	}
	return id, nil
}
