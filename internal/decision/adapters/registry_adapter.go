package adapters

import (
	"context"

	registrycontracts "credo/contracts/registry"
	"credo/internal/decision/ports"
	registryService "credo/internal/evidence/registry/service"
	id "credo/pkg/domain"
)

// RegistryAdapter is an in-process adapter that implements ports.RegistryPort
// by directly calling the registry service. This maintains the hexagonal
// architecture boundaries while keeping everything in a single process.
// When splitting into microservices, this can be replaced with a gRPC adapter
// without changing the decision domain layer.
//
// The adapter maps registry service models to contract types, ensuring
// the decision module only receives PII-light data at the boundary.
type RegistryAdapter struct {
	registryService *registryService.Service
}

// NewRegistryAdapter creates a new in-process registry adapter.
func NewRegistryAdapter(registryService *registryService.Service) ports.RegistryPort {
	return &RegistryAdapter{
		registryService: registryService,
	}
}

// CheckCitizen retrieves citizen record by national ID.
// Uses CitizenWithDetails to get DOB for age derivation, then maps to contract type.
func (a *RegistryAdapter) CheckCitizen(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*registrycontracts.CitizenRecord, error) {
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

// CheckSanctions retrieves sanctions record by national ID.
func (a *RegistryAdapter) CheckSanctions(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*registrycontracts.SanctionsRecord, error) {
	record, err := a.registryService.Sanctions(ctx, userID, nationalID)
	if err != nil {
		return nil, err
	}

	// Map to contract type - only Listed crosses the boundary
	return &registrycontracts.SanctionsRecord{
		Listed: record.Listed,
	}, nil
}
