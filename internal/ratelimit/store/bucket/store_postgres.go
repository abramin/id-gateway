package bucket

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"credo/internal/ratelimit/models"
	"credo/pkg/requestcontext"
)

// PostgresBucketStore persists rate limit counters in PostgreSQL.
type PostgresBucketStore struct {
	db *sql.DB
}

// NewPostgres constructs a PostgreSQL-backed bucket store.
func NewPostgres(db *sql.DB) *PostgresBucketStore {
	return &PostgresBucketStore{db: db}
}

func (s *PostgresBucketStore) Allow(ctx context.Context, key string, limit int, window time.Duration) (*models.RateLimitResult, error) {
	return s.AllowN(ctx, key, 1, limit, window)
}

func (s *PostgresBucketStore) AllowN(ctx context.Context, key string, cost, limit int, windowDuration time.Duration) (*models.RateLimitResult, error) {
	if key == "" {
		return nil, fmt.Errorf("rate limit key is required")
	}
	if limit <= 0 || cost <= 0 {
		return nil, fmt.Errorf("rate limit cost and limit must be positive")
	}
	if windowDuration <= 0 {
		return nil, fmt.Errorf("rate limit window must be positive")
	}

	now := requestcontext.Now(ctx)
	cutoff := now.Add(-windowDuration)
	windowSeconds := int(windowDuration.Seconds())

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin rate limit tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, key); err != nil {
		return nil, fmt.Errorf("acquire rate limit lock: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM rate_limit_events WHERE key = $1 AND occurred_at < $2`, key, cutoff); err != nil {
		return nil, fmt.Errorf("cleanup rate limit events: %w", err)
	}

	var current int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(cost), 0) FROM rate_limit_events WHERE key = $1`, key).Scan(&current); err != nil {
		return nil, fmt.Errorf("count rate limit events: %w", err)
	}

	var oldest sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT MIN(occurred_at) FROM rate_limit_events WHERE key = $1`, key).Scan(&oldest); err != nil {
		return nil, fmt.Errorf("oldest rate limit event: %w", err)
	}

	allowed := current+cost <= limit
	resetAt := now.Add(windowDuration)
	if !allowed && oldest.Valid {
		resetAt = oldest.Time.Add(windowDuration)
	}

	if allowed {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO rate_limit_events (key, occurred_at, cost, window_seconds)
			VALUES ($1, $2, $3, $4)
		`, key, now, cost, windowSeconds)
		if err != nil {
			return nil, fmt.Errorf("insert rate limit event: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit rate limit tx: %w", err)
	}

	remaining := 0
	if allowed {
		remaining = limit - (current + cost)
	}
	return &models.RateLimitResult{
		Allowed:    allowed,
		Limit:      limit,
		Remaining:  remaining,
		ResetAt:    resetAt,
		RetryAfter: retryAfterSeconds(allowed, resetAt, now),
	}, nil
}

func (s *PostgresBucketStore) Reset(ctx context.Context, key string) error {
	if key == "" {
		return fmt.Errorf("rate limit key is required")
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM rate_limit_events WHERE key = $1`, key)
	if err != nil {
		return fmt.Errorf("reset rate limit: %w", err)
	}
	return nil
}

func (s *PostgresBucketStore) GetCurrentCount(ctx context.Context, key string) (int, error) {
	if key == "" {
		return 0, fmt.Errorf("rate limit key is required")
	}

	now := requestcontext.Now(ctx)

	// First, get the window duration from the most recent event
	var windowSeconds sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
		SELECT window_seconds
		FROM rate_limit_events
		WHERE key = $1
		ORDER BY occurred_at DESC
		LIMIT 1
	`, key).Scan(&windowSeconds)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// No events exist for this key
			return 0, nil
		}
		return 0, fmt.Errorf("get rate limit window: %w", err)
	}
	if !windowSeconds.Valid {
		return 0, nil
	}

	// Now count events within the window
	cutoff := now.Add(-time.Duration(windowSeconds.Int64) * time.Second)
	var count int
	err = s.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(cost), 0)
		FROM rate_limit_events
		WHERE key = $1 AND occurred_at >= $2
	`, key, cutoff).Scan(&count)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, fmt.Errorf("get rate limit count: %w", err)
	}
	return count, nil
}
