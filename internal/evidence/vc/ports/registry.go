package ports

import (
	"context"

	registrymodels "credo/internal/evidence/registry/models"
	id "credo/pkg/domain"
)

// RegistryPort defines the interface for registry lookups.
// This is a hexagonal architecture port - the service layer depends on this interface,
// and adapters (in-process, gRPC client, mock) implement it.
type RegistryPort interface {
	// Citizen fetches a citizen record for the given user and national ID.
	// Returns the citizen record or an error if the lookup fails.
	Citizen(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*registrymodels.CitizenRecord, error)
}
