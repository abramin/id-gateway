package models

// CitizenRecord holds registry attributes that may include PII depending on the
// regulated mode.
type CitizenRecord struct {
	NationalID  string
	FullName    string
	DateOfBirth string
	Valid       bool
}

// SanctionsRecord captures sanctions lookups.
type SanctionsRecord struct {
	NationalID string
	Listed     bool
	Source     string
}

type RegistryResult struct {
	Citizen  *CitizenRecord
	Sanction *SanctionsRecord
}

// MinimizeCitizenRecord strips PII when regulated mode is enabled.
func MinimizeCitizenRecord(record CitizenRecord) CitizenRecord {
	return CitizenRecord{
		NationalID:  "",
		FullName:    "",
		DateOfBirth: "",
		Valid:       record.Valid,
	}
}
