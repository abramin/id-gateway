package store

import (
	"context"

	"credo/internal/evidence/vc/models"
	pkgerrors "credo/pkg/domain-errors"
)

var (
	// ErrNotFound keeps storage-specific 404s consistent across implementations.
	ErrNotFound = pkgerrors.New(pkgerrors.CodeNotFound, "record not found")
)

type Store interface {
	Save(ctx context.Context, credential models.VerifiableCredential) error
	FindByID(ctx context.Context, id models.CredentialID) (models.VerifiableCredential, error)
}
