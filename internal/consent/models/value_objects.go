package models

// Purpose labels why data is processed. Purpose binding allows selective
// revocation without affecting other flows.
type Purpose string

const (
	PurposeLogin         Purpose = "login"
	PurposeRegistryCheck Purpose = "registry_check"
	PurposeVCIssuance    Purpose = "vc_issuance"
	PurposeDecision      Purpose = "decision_evaluation"
)

// ValidPurposes is the single source of truth for all valid consent purposes.
var ValidPurposes = map[Purpose]bool{
	PurposeLogin:         true,
	PurposeRegistryCheck: true,
	PurposeVCIssuance:    true,
	PurposeDecision:      true,
}

// IsValid checks if the consent purpose is one of the supported enum values.
func (p Purpose) IsValid() bool {
	return ValidPurposes[p]
}

// Status represents the lifecycle state of a consent record.
type Status string

const (
	StatusActive  Status = "active"
	StatusExpired Status = "expired"
	StatusRevoked Status = "revoked"
)

// IsValid checks if the status is one of the supported enum values.
func (s Status) IsValid() bool {
	return s == StatusActive || s == StatusExpired || s == StatusRevoked
}
