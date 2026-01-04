package service

import (
	"context"
	"sync"
	"time"

	dErrors "credo/pkg/domain-errors"
)

// StoreTx provides a transactional boundary for tenant/client mutations.
// Implementations may wrap a database transaction or an in-memory lock.
type StoreTx interface {
	RunInTx(ctx context.Context, fn func(ctx context.Context) error) error
}

const defaultTxTimeout = 5 * time.Second

// inMemoryStoreTx serializes mutations for in-memory stores.
type inMemoryStoreTx struct {
	mu      sync.Mutex
	timeout time.Duration
}

func newInMemoryStoreTx() *inMemoryStoreTx {
	return &inMemoryStoreTx{}
}

func (t *inMemoryStoreTx) RunInTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return dErrors.Wrap(err, dErrors.CodeTimeout, "transaction aborted: context cancelled")
	}

	timeout := t.timeout
	if timeout == 0 {
		timeout = defaultTxTimeout
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return dErrors.Wrap(err, dErrors.CodeTimeout, "transaction aborted: context cancelled")
	}

	return fn(ctx)
}
