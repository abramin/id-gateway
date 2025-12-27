package adapters

import (
	"context"

	"credo/internal/decision/ports"
	registryService "credo/internal/evidence/registry/service"
	id "credo/pkg/domain"
)

// RegistryAdapter is an in-process adapter that implements ports.RegistryPort
// by directly calling the registry service. This maintains the hexagonal
// architecture boundaries while keeping everything in a single process.
// When splitting into microservices, this can be replaced with a gRPC adapter
// without changing the decision domain layer.
type RegistryAdapter struct {
	registryService *registryService.Service
}

// NewRegistryAdapter creates a new in-process registry adapter
func NewRegistryAdapter(registryService *registryService.Service) ports.RegistryPort {
	return &RegistryAdapter{
		registryService: registryService,
	}
}

// CheckCitizen retrieves citizen record by national ID
func (a *RegistryAdapter) CheckCitizen(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*ports.CitizenRecord, error) {
	record, err := a.registryService.Citizen(ctx, userID, nationalID)
	if err != nil {
		return nil, err
	}

	return &ports.CitizenRecord{
		NationalID:  record.NationalID,
		FullName:    record.FullName,
		DateOfBirth: record.DateOfBirth,
		Valid:       record.Valid,
		CheckedAt:   record.CheckedAt,
	}, nil
}

// CheckSanctions retrieves sanctions record by national ID
func (a *RegistryAdapter) CheckSanctions(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*ports.SanctionsRecord, error) {
	record, err := a.registryService.Sanctions(ctx, userID, nationalID)
	if err != nil {
		return nil, err
	}

	return &ports.SanctionsRecord{
		NationalID: record.NationalID,
		Listed:     record.Listed,
		Source:     record.Source,
		CheckedAt:  record.CheckedAt,
	}, nil
}

// Check performs combined citizen + sanctions lookup
func (a *RegistryAdapter) Check(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*ports.CitizenRecord, *ports.SanctionsRecord, error) {
	result, err := a.registryService.Check(ctx, userID, nationalID)
	if err != nil {
		return nil, nil, err
	}

	citizen := &ports.CitizenRecord{
		NationalID:  result.Citizen.NationalID,
		FullName:    result.Citizen.FullName,
		DateOfBirth: result.Citizen.DateOfBirth,
		Valid:       result.Citizen.Valid,
		CheckedAt:   result.Citizen.CheckedAt,
	}

	sanctions := &ports.SanctionsRecord{
		NationalID: result.Sanction.NationalID,
		Listed:     result.Sanction.Listed,
		Source:     result.Sanction.Source,
		CheckedAt:  result.Sanction.CheckedAt,
	}

	return citizen, sanctions, nil
}
