package registry

// ContractVersion identifies the schema for registry evidence shared across services.
const ContractVersion = "v0.1.0"

// CitizenRecord is the minimal, non-PII citizen evidence used by decision logic.
type CitizenRecord struct {
	DateOfBirth string `json:"date_of_birth"`
	Valid       bool   `json:"valid"`
}

// SanctionsRecord carries the sanctions verdict needed for downstream decisions.
type SanctionsRecord struct {
	Listed bool `json:"listed"`
}
