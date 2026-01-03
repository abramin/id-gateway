package adapters

import (
	"context"

	registrycontracts "credo/contracts/registry"
	registryservice "credo/internal/evidence/registry/service"
	"credo/internal/evidence/vc/ports"
	id "credo/pkg/domain"
)

// RegistryAdapter bridges the registry service into the VC registry port.
// Maps internal registry models to contract types at the boundary.
type RegistryAdapter struct {
	registryService *registryservice.Service
}

// NewRegistryAdapter creates a new in-process registry adapter.
func NewRegistryAdapter(registryService *registryservice.Service) ports.RegistryPort {
	return &RegistryAdapter{registryService: registryService}
}

// Citizen fetches a citizen record for the given user and national ID.
// Maps the internal registry model to the contract type at the boundary,
// exposing only DateOfBirth and Valid to the VC service.
func (a *RegistryAdapter) Citizen(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*registrycontracts.CitizenRecord, error) {
	record, err := a.registryService.CitizenWithDetails(ctx, userID, nationalID)
	if err != nil {
		return nil, err
	}
	// Map to contract type - only DateOfBirth and Valid cross the boundary
	return &registrycontracts.CitizenRecord{
		DateOfBirth: record.DateOfBirth,
		Valid:       record.Valid,
	}, nil
}
