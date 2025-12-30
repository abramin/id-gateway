package store

import (
	"context"

	"credo/internal/evidence/vc/models"
	"credo/pkg/platform/sentinel"
)

// ErrNotFound is returned when a credential is not found in the store.
// Services should translate this to a domain error at their boundary.
var ErrNotFound = sentinel.ErrNotFound

// Store defines the credential persistence interface.
// Implementations return sentinel errors (ErrNotFound) for infrastructure facts.
// Services are responsible for translating these to domain errors.
type Store interface {
	Save(ctx context.Context, credential models.CredentialRecord) error
	FindByID(ctx context.Context, id models.CredentialID) (models.CredentialRecord, error)
}
