package vc

// Package vc hosts the stable, minimal DTOs shared across services for
// verifiable credential evidence. Keep these PII-light and versioned
// independently from any internal VC schemas or persistence models.

// ContractVersion identifies the contract schema version for compatibility checks.
// Bump on breaking changes to the shapes below; consumers can pin or roll forward.
const ContractVersion = "v0.1.0"

// CredentialType identifies the kind of credential.
type CredentialType string

const (
	// CredentialTypeAgeOver18 is the supported credential type for age verification.
	CredentialTypeAgeOver18 CredentialType = "AgeOver18"
)

// CredentialPresence is the minimal contract for credential lookups.
// Used by decision module to check if a valid credential exists without
// exposing the full CredentialRecord.
type CredentialPresence struct {
	Exists bool
	Claims map[string]interface{}
}
