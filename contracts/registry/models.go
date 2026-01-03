// Package registry hosts the stable, minimal DTOs shared across services for
// registry evidence. Keep these PII-light and versioned independently from any
// internal registry schemas or persistence models.
//
// :warning: Wont be needed once protobuf/gRPC is in place for inter-service communication.!
package registry

import (
	"context"

	id "credo/pkg/domain"
)

// ContractVersion identifies the contract schema version for compatibility checks.
// Bump on breaking changes to the shapes below; consumers can pin or roll forward.
const ContractVersion = "v0.1.0"

// Provider defines the interface for registry lookups using contract types.
// Adapters in decision and evidence/vc use this interface to depend on registry
// behavior without importing the registry service package.
type Provider interface {
	CitizenContract(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*CitizenRecord, error)
}

// FullProvider extends Provider with sanctions lookup capability.
// Used by decision module which needs both citizen and sanctions checks.
type FullProvider interface {
	Provider
	SanctionsContract(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*SanctionsRecord, error)
}

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
