package service

import (
	"context"
	"credo/internal/evidence/registry/models"
	"credo/internal/evidence/registry/store"
	"errors"
)

// Service coordinates registry lookups with caching and optional minimisation.
type Service struct {
	citizens  CitizenClient
	sanctions SanctionsClient
	cache     CacheStore
	regulated bool
}

// CitizenClient defines the interface for citizen registry lookups
type CitizenClient interface {
	Lookup(ctx context.Context, nationalID string) (*models.CitizenRecord, error)
}

// SanctionsClient defines the interface for sanctions registry lookups
type SanctionsClient interface {
	Check(ctx context.Context, nationalID string) (*models.SanctionsRecord, error)
}

// CacheStore defines the interface for registry caching operations
type CacheStore interface {
	FindCitizen(ctx context.Context, nationalID string) (*models.CitizenRecord, error)
	SaveCitizen(ctx context.Context, record *models.CitizenRecord) error
	FindSanction(ctx context.Context, nationalID string) (*models.SanctionsRecord, error)
	SaveSanction(ctx context.Context, record *models.SanctionsRecord) error
}

func NewService(citizens CitizenClient, sanctions SanctionsClient, cache CacheStore, regulated bool) *Service {
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
