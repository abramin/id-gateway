package registry

// Package registry hosts the stable, minimal DTOs shared across services for
// registry evidence. Keep these PII-light and versioned independently from any
// internal registry schemas or persistence models.

// ContractVersion identifies the contract schema version for compatibility checks.
// Bump on breaking changes to the shapes below; consumers can pin or roll forward.
const ContractVersion = "v0.1.0"

// CitizenRecord is the minimal, non-PII citizen evidence exposed to other modules
// (e.g., decision). Map richer internal records into this shape at the boundary.
type CitizenRecord struct {
	DateOfBirth string `json:"date_of_birth"`
	Valid       bool   `json:"valid"`
}

// SanctionsRecord carries the sanctions verdict needed for downstream decisions.
// Provider-specific metadata stays inside the registry service; this is the
// contract-friendly, stable surface.
type SanctionsRecord struct {
	Listed bool `json:"listed"`
}
