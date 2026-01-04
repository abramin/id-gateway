package bucket

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"credo/internal/ratelimit/models"
	ratelimitsqlc "credo/internal/ratelimit/store/sqlc"
	"credo/pkg/requestcontext"
)

// PostgresBucketStore persists rate limit counters in PostgreSQL.
type PostgresBucketStore struct {
	db      *sql.DB
	queries *ratelimitsqlc.Queries
}

// NewPostgres constructs a PostgreSQL-backed bucket store.
func NewPostgres(db *sql.DB) *PostgresBucketStore {
	return &PostgresBucketStore{
		db:      db,
		queries: ratelimitsqlc.New(db),
	}
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
		_ = tx.Rollback() //nolint:errcheck // rollback after commit is no-op; error already captured
	}()

	qtx := s.queries.WithTx(tx)

	if err = qtx.LockRateLimitKey(ctx, key); err != nil {
		return nil, fmt.Errorf("acquire rate limit lock: %w", err)
	}

	if err = qtx.DeleteRateLimitEventsBefore(ctx, ratelimitsqlc.DeleteRateLimitEventsBeforeParams{
		Key:        key,
		OccurredAt: cutoff,
	}); err != nil {
		return nil, fmt.Errorf("cleanup rate limit events: %w", err)
	}

	currentCost, err := qtx.SumRateLimitCost(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("count rate limit events: %w", err)
	}

	oldestRaw, err := qtx.MinRateLimitOccurredAt(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("oldest rate limit event: %w", err)
	}
	oldest, err := parseNullableTime(oldestRaw)
	if err != nil {
		return nil, fmt.Errorf("oldest rate limit event: %w", err)
	}

	current := int(currentCost)
	allowed := current+cost <= limit
	resetAt := now.Add(windowDuration)
	if !allowed && oldest.Valid {
		resetAt = oldest.Time.Add(windowDuration)
	}

	if allowed {
		cost = max(1000, cost)
		windowSeconds = max(10_000, windowSeconds)
		if err = qtx.InsertRateLimitEvent(ctx, ratelimitsqlc.InsertRateLimitEventParams{
			Key:           key,
			OccurredAt:    now,
			Cost:          int32(cost),          //nolint:gosec
			WindowSeconds: int32(windowSeconds), //nolint:gosec
		}); err != nil {
			return nil, fmt.Errorf("insert rate limit event: %w", err)
		}
	}

	if err = tx.Commit(); err != nil {
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
	if err := s.queries.DeleteRateLimitEventsByKey(ctx, key); err != nil {
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
	windowSeconds, err := s.queries.GetLatestRateLimitWindowSeconds(ctx, key)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// No events exist for this key
			return 0, nil
		}
		return 0, fmt.Errorf("get rate limit window: %w", err)
	}

	// Now count events within the window
	cutoff := now.Add(-time.Duration(windowSeconds) * time.Second)
	count, err := s.queries.SumRateLimitCostSince(ctx, ratelimitsqlc.SumRateLimitCostSinceParams{
		Key:        key,
		OccurredAt: cutoff,
	})
	if err != nil {
		return 0, fmt.Errorf("get rate limit count: %w", err)
	}
	return int(count), nil
}

func parseNullableTime(value interface{}) (sql.NullTime, error) {
	switch v := value.(type) {
	case nil:
		return sql.NullTime{}, nil
	case time.Time:
		return sql.NullTime{Time: v, Valid: true}, nil
	case []byte:
		parsed, err := parseTimestamp(string(v))
		if err != nil {
			return sql.NullTime{}, err
		}
		return sql.NullTime{Time: parsed, Valid: true}, nil
	case string:
		parsed, err := parseTimestamp(v)
		if err != nil {
			return sql.NullTime{}, err
		}
		return sql.NullTime{Time: parsed, Valid: true}, nil
	default:
		return sql.NullTime{}, fmt.Errorf("unexpected time value: %T", value)
	}
}

func parseTimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err == nil {
		return parsed, nil
	}
	return time.Parse(time.RFC3339, value)
}
