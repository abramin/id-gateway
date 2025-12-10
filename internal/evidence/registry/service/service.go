package registry

import (
	"context"
	"credo/internal/evidence/registry/cache"
	"credo/internal/evidence/registry/models"
	"credo/internal/evidence/registry/store"
	"errors"

	"credo/internal/evidence/registry/clients/citizen"
	"credo/internal/evidence/registry/clients/sanctions"
)

// Service coordinates registry lookups with caching and optional minimisation.
type Service struct {
	citizens  *citizen.MockClient
	sanctions *sanctions.MockClient
	cache     *cache.RegistryCacheStore
	regulated bool
}

func NewService(citizens *citizen.MockClient, sanctions *sanctions.MockClient, cache *cache.RegistryCacheStore, regulated bool) *Service {
	return &Service{
		citizens:  citizens,
		sanctions: sanctions,
		cache:     cache,
		regulated: regulated,
	}
}

func (s *Service) Check(ctx context.Context, nationalID string) (*models.RegistryResult, error) {
	citizen, err := s.Citizen(ctx, nationalID)
	if err != nil {
		return nil, err
	}
	sanctions, err := s.Sanctions(ctx, nationalID)
	if err != nil {
		return nil, err
	}
	return &models.RegistryResult{
		Citizen:  citizen,
		Sanction: sanctions,
	}, nil
}

func (s *Service) Citizen(ctx context.Context, nationalID string) (*models.CitizenRecord, error) {
	if s.cache != nil {
		if cached, err := s.cache.FindCitizen(ctx, nationalID); err == nil {
			return cached, nil
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	record, err := s.citizens.Lookup(ctx, nationalID)
	if err != nil {
		return nil, err
	}
	if s.regulated {
		minimized := models.MinimizeCitizenRecord(*record)
		record = &minimized
	}
	if s.cache != nil {
		_ = s.cache.SaveCitizen(ctx, record)
	}
	return record, nil
}

func (s *Service) Sanctions(ctx context.Context, nationalID string) (*models.SanctionsRecord, error) {
	if s.cache != nil {
		if cached, err := s.cache.FindSanction(ctx, nationalID); err == nil {
			return cached, nil
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	record, err := s.sanctions.Check(ctx, nationalID)
	if err != nil {
		return nil, err
	}
	if s.cache != nil {
		_ = s.cache.SaveSanction(ctx, record)
	}
	return record, nil
}
