package adapters

import (
	"context"

	registrymodels "credo/internal/evidence/registry/models"
	registryservice "credo/internal/evidence/registry/service"
	"credo/internal/evidence/vc/ports"
	id "credo/pkg/domain"
)

// RegistryAdapter bridges the registry service into the VC registry port.
type RegistryAdapter struct {
	registryService *registryservice.Service
}

// NewRegistryAdapter creates a new in-process registry adapter.
func NewRegistryAdapter(registryService *registryservice.Service) ports.RegistryPort {
	return &RegistryAdapter{registryService: registryService}
}

// Citizen fetches a citizen record for the given user and national ID.
// Uses CitizenWithDetails to get full PII for age computation - the VC service
// applies its own minimization to the credential claims before output.
func (a *RegistryAdapter) Citizen(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*registrymodels.CitizenRecord, error) {
	return a.registryService.CitizenWithDetails(ctx, userID, nationalID)
}
