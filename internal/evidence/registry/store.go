package registry

import (
	"context"

	pkgerrors "credo/pkg/domain-errors"
)

var (
	// ErrNotFound keeps storage-specific 404s consistent across implementations.
	ErrNotFound = pkgerrors.New(pkgerrors.CodeNotFound, "record not found")
)

type RegistryCacheStore interface {
	SaveCitizen(ctx context.Context, record CitizenRecord) error
	FindCitizen(ctx context.Context, nationalID string) (CitizenRecord, error)
	SaveSanction(ctx context.Context, record SanctionsRecord) error
	FindSanction(ctx context.Context, nationalID string) (SanctionsRecord, error)
}
