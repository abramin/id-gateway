package adapters

import (
	"context"

	registrycontracts "credo/contracts/registry"
	"credo/internal/evidence/vc/ports"
	id "credo/pkg/domain"
)

// RegistryAdapter bridges the registry service into the VC registry port.
// Uses registry service contract methods to avoid importing internal models.
type RegistryAdapter struct {
	registryService registrycontracts.Provider
}

// NewRegistryAdapter creates a new in-process registry adapter.
func NewRegistryAdapter(registryService registrycontracts.Provider) ports.RegistryPort {
	return &RegistryAdapter{registryService: registryService}
}

// Citizen fetches a citizen record for the given user and national ID.
// Returns contract type directly from the registry service.
func (a *RegistryAdapter) Citizen(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*registrycontracts.CitizenRecord, error) {
	return a.registryService.CitizenContract(ctx, userID, nationalID)
}
