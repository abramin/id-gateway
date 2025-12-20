package audit

import (
	"context"

	id "credo/pkg/domain"
	pkgerrors "credo/pkg/domain-errors"
)

var (
	// ErrNotFound keeps storage-specific 404s consistent across implementations.
	ErrNotFound = pkgerrors.New(pkgerrors.CodeNotFound, "record not found")
)

type Store interface {
	Append(ctx context.Context, event Event) error
	ListByUser(ctx context.Context, userID id.UserID) ([]Event, error)
	ListAll(ctx context.Context) ([]Event, error)
	ListRecent(ctx context.Context, limit int) ([]Event, error)
}
