package authlockout

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"credo/internal/ratelimit/config"
	"credo/internal/ratelimit/models"
	"credo/pkg/requestcontext"
)

// PostgresStore persists auth lockout records in PostgreSQL.
type PostgresStore struct {
	db     *sql.DB
	config *config.AuthLockoutConfig
}

// NewPostgres constructs a PostgreSQL-backed auth lockout store.
func NewPostgres(db *sql.DB, cfg *config.AuthLockoutConfig) *PostgresStore {
	if cfg == nil {
		defaultCfg := config.DefaultConfig().AuthLockout
		cfg = &defaultCfg
	}
	return &PostgresStore{
		db:     db,
		config: cfg,
	}
}

func (s *PostgresStore) Get(ctx context.Context, identifier string) (*models.AuthLockout, error) {
	query := `
		SELECT identifier, failure_count, daily_failures, locked_until, last_failure_at, requires_captcha
		FROM auth_lockouts
		WHERE identifier = $1
	`
	record, err := scanAuthLockout(s.db.QueryRowContext(ctx, query, identifier))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get auth lockout: %w", err)
	}
	return record, nil
}

func (s *PostgresStore) RecordFailure(ctx context.Context, identifier string) (*models.AuthLockout, error) {
	now := requestcontext.Now(ctx)
	query := `
		INSERT INTO auth_lockouts (identifier, failure_count, daily_failures, locked_until, last_failure_at, requires_captcha)
		VALUES ($1, 1, 1, NULL, $2, FALSE)
		ON CONFLICT (identifier) DO UPDATE SET
			failure_count = auth_lockouts.failure_count + 1,
			daily_failures = auth_lockouts.daily_failures + 1,
			last_failure_at = EXCLUDED.last_failure_at
		RETURNING identifier, failure_count, daily_failures, locked_until, last_failure_at, requires_captcha
	`
	record, err := scanAuthLockout(s.db.QueryRowContext(ctx, query, identifier, now))
	if err != nil {
		return nil, fmt.Errorf("record auth failure: %w", err)
	}
	return record, nil
}

func (s *PostgresStore) Clear(ctx context.Context, identifier string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_lockouts WHERE identifier = $1`, identifier)
	if err != nil {
		return fmt.Errorf("clear auth lockout: %w", err)
	}
	return nil
}

func (s *PostgresStore) IsLocked(ctx context.Context, identifier string) (bool, *time.Time, error) {
	var lockedUntil sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT locked_until FROM auth_lockouts WHERE identifier = $1`, identifier).Scan(&lockedUntil)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("check auth lockout: %w", err)
	}

	if lockedUntil.Valid && lockedUntil.Time.After(requestcontext.Now(ctx)) {
		return true, &lockedUntil.Time, nil
	}
	return false, nil, nil
}

func (s *PostgresStore) Update(ctx context.Context, record *models.AuthLockout) error {
	if record == nil {
		return fmt.Errorf("auth lockout record is required")
	}
	query := `
		INSERT INTO auth_lockouts (identifier, failure_count, daily_failures, locked_until, last_failure_at, requires_captcha)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (identifier) DO UPDATE SET
			failure_count = EXCLUDED.failure_count,
			daily_failures = EXCLUDED.daily_failures,
			locked_until = EXCLUDED.locked_until,
			last_failure_at = EXCLUDED.last_failure_at,
			requires_captcha = EXCLUDED.requires_captcha
	`
	_, err := s.db.ExecContext(ctx, query,
		record.Identifier,
		record.FailureCount,
		record.DailyFailures,
		record.LockedUntil,
		record.LastFailureAt,
		record.RequiresCaptcha,
	)
	if err != nil {
		return fmt.Errorf("update auth lockout: %w", err)
	}
	return nil
}

func (s *PostgresStore) ResetFailureCount(ctx context.Context) (int, error) {
	cutoff := time.Now().Add(-s.config.WindowDuration)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin reset failure count: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var total int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(failure_count), 0) FROM auth_lockouts WHERE last_failure_at < $1`, cutoff).Scan(&total); err != nil {
		return 0, fmt.Errorf("sum failure count: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE auth_lockouts SET failure_count = 0 WHERE last_failure_at < $1`, cutoff); err != nil {
		return 0, fmt.Errorf("reset failure count: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit reset failure count: %w", err)
	}
	return total, nil
}

func (s *PostgresStore) ResetDailyFailures(ctx context.Context) (int, error) {
	cutoff := time.Now().Add(-24 * time.Hour)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin reset daily failures: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var total int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(daily_failures), 0) FROM auth_lockouts WHERE last_failure_at < $1`, cutoff).Scan(&total); err != nil {
		return 0, fmt.Errorf("sum daily failures: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE auth_lockouts SET daily_failures = 0 WHERE last_failure_at < $1`, cutoff); err != nil {
		return 0, fmt.Errorf("reset daily failures: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit reset daily failures: %w", err)
	}
	return total, nil
}

type authLockoutRow interface {
	Scan(dest ...any) error
}

func scanAuthLockout(row authLockoutRow) (*models.AuthLockout, error) {
	var record models.AuthLockout
	var lockedUntil sql.NullTime
	if err := row.Scan(&record.Identifier, &record.FailureCount, &record.DailyFailures, &lockedUntil, &record.LastFailureAt, &record.RequiresCaptcha); err != nil {
		return nil, err
	}
	if lockedUntil.Valid {
		record.LockedUntil = &lockedUntil.Time
	}
	return &record, nil
}
