package service

import (
	"context"

	registrycontracts "credo/contracts/registry"
	id "credo/pkg/domain"
)

// CitizenContract performs a citizen lookup returning contract types for cross-module use.
// This method wraps CitizenWithDetails and maps to the stable contract type, allowing
// consuming modules (e.g., decision) to depend on contracts rather than internal models.
func (s *Service) CitizenContract(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*registrycontracts.CitizenRecord, error) {
	record, err := s.CitizenWithDetails(ctx, userID, nationalID)
	if err != nil {
		return nil, err
	}
	return &registrycontracts.CitizenRecord{
		DateOfBirth: record.DateOfBirth,
		Valid:       record.Valid,
	}, nil
}

// SanctionsContract performs a sanctions lookup returning contract types for cross-module use.
// This method wraps Sanctions and maps to the stable contract type, allowing consuming
// modules (e.g., decision) to depend on contracts rather than internal models.
func (s *Service) SanctionsContract(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*registrycontracts.SanctionsRecord, error) {
	record, err := s.Sanctions(ctx, userID, nationalID)
	if err != nil {
		return nil, err
	}
	return &registrycontracts.SanctionsRecord{
		Listed: record.Listed,
	}, nil
}
