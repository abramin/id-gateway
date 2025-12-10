package vc

import (
	"context"

	pkgerrors "credo/pkg/domain-errors"
)

var (
	// ErrNotFound keeps storage-specific 404s consistent across implementations.
	ErrNotFound = pkgerrors.New(pkgerrors.CodeNotFound, "record not found")
)

type Store interface {
	Save(ctx context.Context, credential IssueResult) error
	FindByID(ctx context.Context, id string) (IssueResult, error)
}
