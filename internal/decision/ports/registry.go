package ports

import (
	"context"

	registrycontracts "credo/contracts/registry"
	id "credo/pkg/domain"
)

// RegistryPort defines the interface for registry lookups.
// This port allows the decision engine to fetch identity evidence
// without depending on gRPC, HTTP, or specific registry implementations.
//
// The port uses contract types (credo/contracts/registry) which contain
// only the minimal, PII-light data needed for decision making.
type RegistryPort interface {
	// CheckCitizen retrieves citizen record by national ID.
	// Returns contract-compliant data (DateOfBirth, Valid only).
	// userID is required for consent verification.
	CheckCitizen(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*registrycontracts.CitizenRecord, error)

	// CheckSanctions retrieves sanctions record by national ID.
	// Returns contract-compliant data (Listed only).
	// userID is required for consent verification.
	CheckSanctions(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*registrycontracts.SanctionsRecord, error)
}
