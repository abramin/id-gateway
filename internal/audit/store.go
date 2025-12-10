package audit

import (
	"context"

	pkgerrors "credo/pkg/domain-errors"
)

var (
	// ErrNotFound keeps storage-specific 404s consistent across implementations.
	ErrNotFound = pkgerrors.New(pkgerrors.CodeNotFound, "record not found")
)

type Store interface {
	Append(ctx context.Context, event Event) error
	ListByUser(ctx context.Context, userID string) ([]Event, error)
}
