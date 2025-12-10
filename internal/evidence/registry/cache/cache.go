package cache

import (
	"context"
	"credo/internal/evidence/registry/models"
)

type RegistryCacheStore struct {
	// *[string[string]*[string[string}

}

func (r RegistryCacheStore) FindCitizen(ctx context.Context, nationalID string) (*models.CitizenRecord, error) {
	panic("unimplemented")
}

func (r RegistryCacheStore) FindSanction(ctx context.Context, nationalID string) (*models.SanctionsRecord, error) {
	panic("unimplemented")
}

func (r RegistryCacheStore) SaveSanction(ctx context.Context, param any) error {
	panic("unimplemented")
}

func (r RegistryCacheStore) SaveCitizen(ctx context.Context, param any) error {
	panic("unimplemented")
}
