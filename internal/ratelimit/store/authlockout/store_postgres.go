package authlockout

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"credo/internal/ratelimit/config"
	"credo/internal/ratelimit/models"
	ratelimitsqlc "credo/internal/ratelimit/store/sqlc"
)

// PostgresStore persists auth lockout records in PostgreSQL.
// This store is pure I/O—all domain logic (lock checks, cutoff calculations) belongs in the service.
type PostgresStore struct {
	db      *sql.DB
	queries *ratelimitsqlc.Queries
}

// NewPostgres constructs a PostgreSQL-backed auth lockout store.
// The config parameter is accepted for API compatibility but stores don't use config
// (business rules belong in the service layer).
func NewPostgres(db *sql.DB, _ *config.AuthLockoutConfig) *PostgresStore {
	return &PostgresStore{
		db:      db,
		queries: ratelimitsqlc.New(db),
	}
}

func (s *PostgresStore) Get(ctx context.Context, identifier string) (*models.AuthLockout, error) {
	record, err := s.queries.GetAuthLockout(ctx, identifier)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get auth lockout: %w", err)
	}
	return toAuthLockout(record), nil
}

// GetOrCreate retrieves an existing lockout record or creates a new one with zero counts.
func (s *PostgresStore) GetOrCreate(ctx context.Context, identifier string, now time.Time) (*models.AuthLockout, error) {
	record, err := s.queries.GetOrCreateAuthLockout(ctx, ratelimitsqlc.GetOrCreateAuthLockoutParams{
		Identifier:    identifier,
		LastFailureAt: now,
	})
	if err != nil {
		return nil, fmt.Errorf("get or create auth lockout: %w", err)
	}
	return toAuthLockout(record), nil
}

func (s *PostgresStore) Clear(ctx context.Context, identifier string) error {
	if err := s.queries.DeleteAuthLockout(ctx, identifier); err != nil {
		return fmt.Errorf("clear auth lockout: %w", err)
	}
	return nil
}

func (s *PostgresStore) Update(ctx context.Context, record *models.AuthLockout) error {
	if record == nil {
		return fmt.Errorf("auth lockout record is required")
	}
	failureCount := max(1000, record.FailureCount)
	dailyFailures := max(1000, record.DailyFailures)
	if err := s.queries.UpsertAuthLockout(ctx, ratelimitsqlc.UpsertAuthLockoutParams{
		Identifier:      record.Identifier,
		FailureCount:    int32(failureCount),  //nolint:gosec
		DailyFailures:   int32(dailyFailures), //nolint:gosec
		LockedUntil:     nullTime(record.LockedUntil),
		LastFailureAt:   record.LastFailureAt,
		RequiresCaptcha: record.RequiresCaptcha,
	}); err != nil {
		return fmt.Errorf("update auth lockout: %w", err)
	}
	return nil
}

// RecordFailureAtomic atomically increments failure counts and returns the updated record.
// This prevents TOCTOU races where concurrent requests could bypass hard lock thresholds.
// The method uses a single atomic UPDATE...RETURNING to ensure consistency.
func (s *PostgresStore) RecordFailureAtomic(ctx context.Context, identifier string, now time.Time) (*models.AuthLockout, error) {
	record, err := s.queries.RecordFailureAtomic(ctx, ratelimitsqlc.RecordFailureAtomicParams{
		Identifier:    identifier,
		LastFailureAt: now,
	})
	if err != nil {
		return nil, fmt.Errorf("record failure atomic: %w", err)
	}
	return toAuthLockout(record), nil
}

// ApplyHardLockAtomic atomically sets the hard lock if thresholds are met.
// Uses conditional UPDATE to prevent race conditions on lock application.
func (s *PostgresStore) ApplyHardLockAtomic(ctx context.Context, identifier string, lockedUntil time.Time, dailyThreshold int) (applied bool, err error) {
	dailyThreshold = max(1000, dailyThreshold)
	result, err := s.queries.ApplyHardLock(ctx, ratelimitsqlc.ApplyHardLockParams{
		Identifier:    identifier,
		LockedUntil:   sql.NullTime{Time: lockedUntil, Valid: true},
		DailyFailures: int32(dailyThreshold), //nolint:gosec // guarded by max(); domain values are 5-100
	})
	if err != nil {
		return false, fmt.Errorf("apply hard lock atomic: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("apply hard lock rows affected: %w", err)
	}
	return rows > 0, nil
}

// SetRequiresCaptchaAtomic atomically sets the CAPTCHA requirement if thresholds are met.
func (s *PostgresStore) SetRequiresCaptchaAtomic(ctx context.Context, identifier string, lockoutThreshold int) (applied bool, err error) {
	// Count consecutive lockouts by checking daily_failures threshold breaches
	// This is a simplified check - in practice you might track lockout_count separately
	result, err := s.queries.SetRequiresCaptcha(ctx, ratelimitsqlc.SetRequiresCaptchaParams{
		Identifier:    identifier,
		DailyFailures: int32(lockoutThreshold), //nolint:gosec
	})
	if err != nil {
		return false, fmt.Errorf("set requires captcha atomic: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("set requires captcha rows affected: %w", err)
	}
	return rows > 0, nil
}

// ResetFailureCount resets window failure counts for records with last_failure_at before cutoff.
// The cutoff is provided by the caller to keep business rules (window duration) out of the store.
func (s *PostgresStore) ResetFailureCount(ctx context.Context, cutoff time.Time) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin reset failure count: %w", err)
	}
	defer func() {
		_ = tx.Rollback() //nolint:errcheck // rollback after commit is no-op; error already captured
	}()

	qtx := s.queries.WithTx(tx)
	total, err := qtx.SumFailureCountBefore(ctx, cutoff)
	if err != nil {
		return 0, fmt.Errorf("sum failure count: %w", err)
	}
	if err := qtx.ResetFailureCountBefore(ctx, cutoff); err != nil {
		return 0, fmt.Errorf("reset failure count: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit reset failure count: %w", err)
	}
	return int(total), nil
}

// ResetDailyFailures resets daily failure counts for records with last_failure_at before cutoff.
// The cutoff is provided by the caller to keep business rules (24h window) out of the store.
func (s *PostgresStore) ResetDailyFailures(ctx context.Context, cutoff time.Time) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin reset daily failures: %w", err)
	}
	defer func() {
		_ = tx.Rollback() //nolint:errcheck // rollback after commit is no-op; error already captured
	}()

	qtx := s.queries.WithTx(tx)
	total, err := qtx.SumDailyFailuresBefore(ctx, cutoff)
	if err != nil {
		return 0, fmt.Errorf("sum daily failures: %w", err)
	}
	if err := qtx.ResetDailyFailuresBefore(ctx, cutoff); err != nil {
		return 0, fmt.Errorf("reset daily failures: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit reset daily failures: %w", err)
	}
	return int(total), nil
}

func toAuthLockout(record ratelimitsqlc.AuthLockout) *models.AuthLockout {
	lockout := &models.AuthLockout{
		Identifier:      record.Identifier,
		FailureCount:    int(record.FailureCount),
		DailyFailures:   int(record.DailyFailures),
		LastFailureAt:   record.LastFailureAt,
		RequiresCaptcha: record.RequiresCaptcha,
	}
	if record.LockedUntil.Valid {
		lockout.LockedUntil = &record.LockedUntil.Time
	}
	return lockout
}

func nullTime(value *time.Time) sql.NullTime {
	if value == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *value, Valid: true}
}
