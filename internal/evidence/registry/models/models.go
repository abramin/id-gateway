package models

import "time"

// CitizenRecord holds registry attributes that may include PII depending on the
// regulated mode.
type CitizenRecord struct {
	NationalID  string
	FullName    string
	DateOfBirth string
	Address     string
	Valid       bool
	CheckedAt   time.Time
}

// SanctionsRecord captures sanctions lookups.
type SanctionsRecord struct {
	NationalID string
	Listed     bool
	Source     string
	CheckedAt  time.Time
}

// RegistryResult holds the combined results of citizen and sanctions lookups.
type RegistryResult struct {
	Citizen  *CitizenRecord
	Sanction *SanctionsRecord
}
