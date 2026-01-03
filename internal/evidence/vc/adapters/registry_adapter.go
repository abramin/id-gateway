package adapters

import (
	"context"

	registrycontracts "credo/contracts/registry"
	"credo/internal/evidence/vc/ports"
	id "credo/pkg/domain"
)

// registryContractProvider defines the interface for registry lookups using contract types.
// Defined locally to avoid coupling to registry service package.
// The registry service implements this method to return contract types directly.
type registryContractProvider interface {
	CitizenContract(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*registrycontracts.CitizenRecord, error)
}

// RegistryAdapter bridges the registry service into the VC registry port.
// Uses registry service contract methods to avoid importing internal models.
type RegistryAdapter struct {
	registryService registryContractProvider
}

// NewRegistryAdapter creates a new in-process registry adapter.
func NewRegistryAdapter(registryService registryContractProvider) ports.RegistryPort {
	return &RegistryAdapter{registryService: registryService}
}

// Citizen fetches a citizen record for the given user and national ID.
// Returns contract type directly from the registry service.
func (a *RegistryAdapter) Citizen(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*registrycontracts.CitizenRecord, error) {
	return a.registryService.CitizenContract(ctx, userID, nationalID)
}
