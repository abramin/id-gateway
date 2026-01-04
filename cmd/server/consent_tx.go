package main

import (
	"context"
	"database/sql"
	"time"

	consentservice "credo/internal/consent/service"
	consentstore "credo/internal/consent/store"
	dErrors "credo/pkg/domain-errors"
)

const defaultConsentTxTimeout = 5 * time.Second

type consentPostgresTx struct {
	db      *sql.DB
	timeout time.Duration
}

func newConsentPostgresTx(db *sql.DB) *consentPostgresTx {
	return &consentPostgresTx{db: db}
}

func (t *consentPostgresTx) RunInTx(ctx context.Context, fn func(ctx context.Context, store consentservice.Store) error) error {
	if err := ctx.Err(); err != nil {
		return dErrors.Wrap(err, dErrors.CodeTimeout, "transaction aborted: context cancelled")
	}

	timeout := t.timeout
	if timeout == 0 {
		timeout = defaultConsentTxTimeout
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

	if err := fn(ctx, consentstore.NewPostgresTx(tx)); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}
