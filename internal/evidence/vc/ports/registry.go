package ports

import (
	"context"

	registrycontracts "credo/contracts/registry"
	id "credo/pkg/domain"
)

// RegistryPort defines the interface for registry lookups.
// This is a hexagonal architecture port - the service layer depends on this interface,
// and adapters (in-process, gRPC client, mock) implement it.
type RegistryPort interface {
	// Citizen fetches a citizen record for the given user and national ID.
	// Returns the citizen record (contract type) or an error if the lookup fails.
	Citizen(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*registrycontracts.CitizenRecord, error)
}
