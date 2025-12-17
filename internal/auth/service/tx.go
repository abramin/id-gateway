package service

import (
	"context"
)

// AuthStoreTx provides a transactional boundary for auth-related store mutations.
// Implementations may wrap a database transaction or, in-memory, a coarse lock.
type AuthStoreTx interface {
	RunInTx(ctx context.Context, fn func(stores TxAuthStores) error) error
}
