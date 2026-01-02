package globalthrottle

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"credo/internal/ratelimit/config"
	"credo/pkg/requestcontext"
)

const (
	bucketSecond = "second"
	bucketHour   = "hour"
)

// PostgresStore persists global throttle counters in PostgreSQL.
type PostgresStore struct {
	db            *sql.DB
	perSecondLimit int
	perHourLimit   int
}

// NewPostgres constructs a PostgreSQL-backed global throttle store.
func NewPostgres(db *sql.DB, cfg *config.GlobalLimit) *PostgresStore {
	if cfg == nil {
		defaultCfg := config.DefaultConfig().Global
		cfg = &defaultCfg
	}
	return &PostgresStore{
		db:             db,
		perSecondLimit: cfg.GlobalPerSecond,
		perHourLimit:   cfg.PerInstancePerHour,
	}
}

// IncrementGlobal increments the global counter and checks if the request is blocked.
func (s *PostgresStore) IncrementGlobal(ctx context.Context) (count int, blocked bool, err error) {
	now := requestcontext.Now(ctx)
	currentSecond := now.Truncate(time.Second)
	currentHour := now.Truncate(time.Hour)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, fmt.Errorf("begin global throttle tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	secStart, secCount, err := s.loadBucket(ctx, tx, bucketSecond, currentSecond)
	if err != nil {
		return 0, false, err
	}
	hourStart, hourCount, err := s.loadBucket(ctx, tx, bucketHour, currentHour)
	if err != nil {
		return 0, false, err
	}

	if secCount+1 > s.perSecondLimit {
		if err := tx.Commit(); err != nil {
			return 0, false, fmt.Errorf("commit global throttle tx: %w", err)
		}
		return secCount, true, nil
	}
	if hourCount+1 > s.perHourLimit {
		if err := tx.Commit(); err != nil {
			return 0, false, fmt.Errorf("commit global throttle tx: %w", err)
		}
		return hourCount, true, nil
	}

	secCount++
	hourCount++
	if err := s.updateBucket(ctx, tx, bucketSecond, secStart, secCount); err != nil {
		return 0, false, err
	}
	if err := s.updateBucket(ctx, tx, bucketHour, hourStart, hourCount); err != nil {
		return 0, false, err
	}

	if err := tx.Commit(); err != nil {
		return 0, false, fmt.Errorf("commit global throttle tx: %w", err)
	}
	return secCount, false, nil
}

// GetGlobalCount returns the current count in the per-second window.
func (s *PostgresStore) GetGlobalCount(ctx context.Context) (count int, err error) {
	now := requestcontext.Now(ctx).Truncate(time.Second)
	var bucketStart time.Time
	var current int
	query := `SELECT bucket_start, count FROM global_throttle WHERE bucket_type = $1`
	if err := s.db.QueryRowContext(ctx, query, bucketSecond).Scan(&bucketStart, &current); err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, fmt.Errorf("get global count: %w", err)
	}
	if bucketStart != now {
		return 0, nil
	}
	return current, nil
}

func (s *PostgresStore) loadBucket(ctx context.Context, tx *sql.Tx, bucketType string, current time.Time) (time.Time, int, error) {
	var bucketStart time.Time
	var count int
	query := `
		SELECT bucket_start, count
		FROM global_throttle
		WHERE bucket_type = $1
		FOR UPDATE
	`
	err := tx.QueryRowContext(ctx, query, bucketType).Scan(&bucketStart, &count)
	if err != nil {
		if err == sql.ErrNoRows {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO global_throttle (bucket_type, bucket_start, count)
				VALUES ($1, $2, 0)
				ON CONFLICT (bucket_type) DO NOTHING
			`, bucketType, current); err != nil {
				return time.Time{}, 0, fmt.Errorf("insert global throttle bucket: %w", err)
			}
			if err := tx.QueryRowContext(ctx, query, bucketType).Scan(&bucketStart, &count); err != nil {
				return time.Time{}, 0, fmt.Errorf("reload global throttle bucket: %w", err)
			}
		} else {
			return time.Time{}, 0, fmt.Errorf("load global throttle bucket: %w", err)
		}
	}

	if !bucketStart.Equal(current) {
		bucketStart = current
		count = 0
		if _, err := tx.ExecContext(ctx, `UPDATE global_throttle SET bucket_start = $2, count = 0 WHERE bucket_type = $1`, bucketType, bucketStart); err != nil {
			return time.Time{}, 0, fmt.Errorf("reset global throttle bucket: %w", err)
		}
	}
	return bucketStart, count, nil
}

func (s *PostgresStore) updateBucket(ctx context.Context, tx *sql.Tx, bucketType string, bucketStart time.Time, count int) error {
	_, err := tx.ExecContext(ctx, `
		UPDATE global_throttle
		SET bucket_start = $2, count = $3
		WHERE bucket_type = $1
	`, bucketType, bucketStart, count)
	if err != nil {
		return fmt.Errorf("update global throttle bucket: %w", err)
	}
	return nil
}
