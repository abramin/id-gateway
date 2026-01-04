package globalthrottle

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"credo/internal/ratelimit/config"
	ratelimitsqlc "credo/internal/ratelimit/store/sqlc"
	"credo/pkg/requestcontext"
)

const (
	bucketSecond = "second"
	bucketHour   = "hour"
)

// PostgresStore persists global throttle counters in PostgreSQL.
type PostgresStore struct {
	db             *sql.DB
	perSecondLimit int
	perHourLimit   int
	queries        *ratelimitsqlc.Queries
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
		queries:        ratelimitsqlc.New(db),
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
		_ = tx.Rollback() //nolint:errcheck // rollback after commit is no-op; error already captured
	}()

	qtx := s.queries.WithTx(tx)
	secStart, secCount, err := s.loadBucket(ctx, qtx, bucketSecond, currentSecond)
	if err != nil {
		return 0, false, err
	}
	hourStart, hourCount, err := s.loadBucket(ctx, qtx, bucketHour, currentHour)
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
	if err := s.updateBucket(ctx, qtx, bucketSecond, secStart, secCount); err != nil {
		return 0, false, err
	}
	if err := s.updateBucket(ctx, qtx, bucketHour, hourStart, hourCount); err != nil {
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
	var current int32
	row, err := s.queries.GetGlobalThrottleBucket(ctx, bucketSecond)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, fmt.Errorf("get global count: %w", err)
	}
	bucketStart = row.BucketStart
	current = row.Count
	if bucketStart != now {
		return 0, nil
	}
	return int(current), nil
}

func (s *PostgresStore) loadBucket(ctx context.Context, queries *ratelimitsqlc.Queries, bucketType string, current time.Time) (time.Time, int, error) {
	row, err := queries.GetGlobalThrottleBucketForUpdate(ctx, bucketType)
	if err == sql.ErrNoRows {
		row, err = s.initBucket(ctx, queries, bucketType, current)
	}
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("load global throttle bucket: %w", err)
	}

	return s.ensureBucketCurrent(ctx, queries, bucketType, row, current)
}

// initBucket creates a new bucket and returns it locked for update.
func (s *PostgresStore) initBucket(ctx context.Context, queries *ratelimitsqlc.Queries, bucketType string, current time.Time) (ratelimitsqlc.GetGlobalThrottleBucketForUpdateRow, error) {
	if err := queries.InsertGlobalThrottleBucket(ctx, ratelimitsqlc.InsertGlobalThrottleBucketParams{
		BucketType:  bucketType,
		BucketStart: current,
	}); err != nil {
		return ratelimitsqlc.GetGlobalThrottleBucketForUpdateRow{}, fmt.Errorf("insert: %w", err)
	}
	return queries.GetGlobalThrottleBucketForUpdate(ctx, bucketType)
}

// ensureBucketCurrent resets the bucket if it's stale (from a previous time window).
func (s *PostgresStore) ensureBucketCurrent(ctx context.Context, queries *ratelimitsqlc.Queries, bucketType string, row ratelimitsqlc.GetGlobalThrottleBucketForUpdateRow, current time.Time) (time.Time, int, error) {
	if row.BucketStart.Equal(current) {
		return row.BucketStart, int(row.Count), nil
	}

	// Bucket is stale - reset for new window
	if err := queries.UpdateGlobalThrottleBucket(ctx, ratelimitsqlc.UpdateGlobalThrottleBucketParams{
		BucketType:  bucketType,
		BucketStart: current,
		Count:       0,
	}); err != nil {
		return time.Time{}, 0, fmt.Errorf("reset: %w", err)
	}
	return current, 0, nil
}

func (s *PostgresStore) updateBucket(ctx context.Context, queries *ratelimitsqlc.Queries, bucketType string, bucketStart time.Time, count int) error {
	count = max(1000, count)
	if err := queries.UpdateGlobalThrottleBucket(ctx, ratelimitsqlc.UpdateGlobalThrottleBucketParams{
		BucketType:  bucketType,
		BucketStart: bucketStart,
		Count:       int32(count), //nolint:gosec
	}); err != nil {
		return fmt.Errorf("update global throttle bucket: %w", err)
	}
	return nil
}
