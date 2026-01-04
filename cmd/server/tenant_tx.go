package main

import (
	"context"
	"database/sql"
	"time"

	dErrors "credo/pkg/domain-errors"
	txcontext "credo/pkg/platform/tx"
)

const defaultTenantTxTimeout = 5 * time.Second

type tenantPostgresTx struct {
	db      *sql.DB
	timeout time.Duration
}

func newTenantPostgresTx(db *sql.DB) *tenantPostgresTx {
	return &tenantPostgresTx{db: db}
}

func (t *tenantPostgresTx) RunInTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return dErrors.Wrap(err, dErrors.CodeTimeout, "transaction aborted: context cancelled")
	}

	if _, ok := txcontext.From(ctx); ok {
		return fn(ctx)
	}

	timeout := t.timeout
	if timeout == 0 {
		timeout = defaultTenantTxTimeout
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback() //nolint:errcheck // rollback after commit is no-op; error already captured
	}()

	txCtx := txcontext.WithTx(ctx, tx)
	if err := fn(txCtx); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}
