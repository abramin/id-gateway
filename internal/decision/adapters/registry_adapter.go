package adapters

import (
	"context"

	registrycontracts "credo/contracts/registry"
	"credo/internal/decision/ports"
	id "credo/pkg/domain"
)

// registryContractProvider defines the interface for registry lookups using contract types.
// Defined locally to avoid coupling to registry service package.
// The registry service implements these methods to return contract types directly,
// eliminating the need for this adapter to import internal registry models.
type registryContractProvider interface {
	CitizenContract(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*registrycontracts.CitizenRecord, error)
	SanctionsContract(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*registrycontracts.SanctionsRecord, error)
}

// RegistryAdapter is an in-process adapter that implements ports.RegistryPort
// by directly calling the registry service. This maintains the hexagonal
// architecture boundaries while keeping everything in a single process.
// When splitting into microservices, this can be replaced with a gRPC adapter
// without changing the decision domain layer.
//
// The adapter uses registry service contract methods, ensuring the decision
// module depends only on stable contract types, not internal registry models.
type RegistryAdapter struct {
	registryService registryContractProvider
}

// NewRegistryAdapter creates a new in-process registry adapter.
func NewRegistryAdapter(registryService registryContractProvider) ports.RegistryPort {
	return &RegistryAdapter{
		registryService: registryService,
	}
}

// CheckCitizen retrieves citizen record by national ID.
// Side effects: calls the registry service and may perform external I/O.
func (a *RegistryAdapter) CheckCitizen(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*registrycontracts.CitizenRecord, error) {
	return a.registryService.CitizenContract(ctx, userID, nationalID)
}

// CheckSanctions retrieves sanctions record by national ID.
// Side effects: calls the registry service and may perform external I/O.
func (a *RegistryAdapter) CheckSanctions(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*registrycontracts.SanctionsRecord, error) {
	return a.registryService.SanctionsContract(ctx, userID, nationalID)
}
