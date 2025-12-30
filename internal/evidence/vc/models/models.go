package models

import (
	"strings"
	"time"

	"github.com/google/uuid"

	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
)

// CredentialType captures the supported credential types.
type CredentialType string

const (
	// CredentialTypeAgeOver18 is the supported credential type for age verification.
	CredentialTypeAgeOver18 CredentialType = "AgeOver18"

	// IssuerCredo is the issuer name for credentials issued by this service.
	IssuerCredo = "credo"

	// VerifiedViaNationalRegistry indicates the source of verification.
	VerifiedViaNationalRegistry = "national_registry"

	credentialIDPrefix = "vc_"
)

// ParseCredentialType validates a credential type string and returns the domain type.
func ParseCredentialType(value string) (CredentialType, error) {
	if strings.TrimSpace(value) == "" {
		return "", dErrors.New(dErrors.CodeInvalidInput, "type is required")
	}
	if value != string(CredentialTypeAgeOver18) {
		return "", dErrors.New(dErrors.CodeInvalidInput, "unsupported credential type")
	}
	return CredentialType(value), nil
}

// CredentialID is the prefixed identifier for issued credentials.
type CredentialID string

// NewCredentialID generates a new credential ID with a stable prefix.
func NewCredentialID() CredentialID {
	return CredentialID(credentialIDPrefix + uuid.NewString())
}

// ParseCredentialID validates and parses a credential ID string.
func ParseCredentialID(value string) (CredentialID, error) {
	if strings.TrimSpace(value) == "" {
		return "", dErrors.New(dErrors.CodeInvalidInput, "credential_id is required")
	}
	if !strings.HasPrefix(value, credentialIDPrefix) {
		return "", dErrors.New(dErrors.CodeInvalidInput, "credential_id must start with vc_")
	}
	if _, err := uuid.Parse(strings.TrimPrefix(value, credentialIDPrefix)); err != nil {
		return "", dErrors.New(dErrors.CodeInvalidInput, "invalid credential_id format")
	}
	return CredentialID(value), nil
}

// String returns the credential ID as a string.
func (id CredentialID) String() string {
	return string(id)
}

// Claims represents a set of verifiable credential claims.
type Claims map[string]interface{}

// IssueRequest captures the data required to issue a credential.
type IssueRequest struct {
	UserID     id.UserID
	Type       CredentialType
	NationalID id.NationalID
}

// CredentialRecord represents an issued credential for persistence and API responses.
// This is the infrastructure model; see domain/credential.Credential for the domain aggregate.
type CredentialRecord struct {
	ID       CredentialID
	Type     CredentialType
	Subject  id.UserID
	Issuer   string
	IssuedAt time.Time
	Claims   Claims
}

// VerifyResult reports the validity of a credential lookup.
type VerifyResult struct {
	Valid      bool
	Credential *CredentialRecord
	Reason     string
}
