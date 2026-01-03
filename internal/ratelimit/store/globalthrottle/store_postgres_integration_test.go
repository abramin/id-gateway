//go:build integration

package globalthrottle_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"credo/internal/ratelimit/config"
	"credo/internal/ratelimit/store/globalthrottle"
	"credo/pkg/requestcontext"
	"credo/pkg/testutil/containers"
)

type PostgresStoreSuite struct {
	suite.Suite
	postgres *containers.PostgresContainer
}

func TestPostgresStoreSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	suite.Run(t, new(PostgresStoreSuite))
}

func (s *PostgresStoreSuite) SetupSuite() {
	mgr := containers.GetManager()
	s.postgres = mgr.GetPostgres(s.T())
}

func (s *PostgresStoreSuite) SetupTest() {
	ctx := context.Background()
	err := s.postgres.TruncateTables(ctx, "global_throttle")
	s.Require().NoError(err)
}

// TestConcurrentGlobalIncrement verifies that concurrent increments correctly
// enforce the global limit (total count equals allowed increments).
func (s *PostgresStoreSuite) TestConcurrentGlobalIncrement() {
	ctx := context.Background()
	cfg := &config.GlobalLimit{
		GlobalPerSecond:    20,
		PerInstancePerHour: 1000,
	}
	store := globalthrottle.NewPostgres(s.postgres.DB, cfg)

	const goroutines = 50
	var wg sync.WaitGroup
	var allowedCount atomic.Int32
	var blockedCount atomic.Int32
	var errors atomic.Int32

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			_, blocked, err := store.IncrementGlobal(ctx)
			if err != nil {
				errors.Add(1)
				return
			}
			if blocked {
				blockedCount.Add(1)
			} else {
				allowedCount.Add(1)
			}
		}()
	}

	wg.Wait()

	s.Equal(int32(0), errors.Load(), "no errors expected")
	// Exactly 'limit' should be allowed (20 per second)
	s.Equal(int32(cfg.GlobalPerSecond), allowedCount.Load(),
		"exactly %d requests should be allowed", cfg.GlobalPerSecond)
	s.Equal(int32(goroutines-cfg.GlobalPerSecond), blockedCount.Load(),
		"remaining requests should be blocked")
}

// TestBucketResetRace verifies correct bucket reset at second boundary.
func (s *PostgresStoreSuite) TestBucketResetRace() {
	ctx := context.Background()
	cfg := &config.GlobalLimit{
		GlobalPerSecond:    5,
		PerInstancePerHour: 1000,
	}
	store := globalthrottle.NewPostgres(s.postgres.DB, cfg)

	// Fill up the limit
	for i := 0; i < cfg.GlobalPerSecond; i++ {
		_, blocked, err := store.IncrementGlobal(ctx)
		s.Require().NoError(err)
		s.False(blocked)
	}

	// Should be blocked now
	_, blocked, err := store.IncrementGlobal(ctx)
	s.Require().NoError(err)
	s.True(blocked)

	// Wait for bucket to reset (next second)
	time.Sleep(1100 * time.Millisecond)

	// Should be allowed again
	_, blocked, err = store.IncrementGlobal(ctx)
	s.Require().NoError(err)
	s.False(blocked, "should be allowed after second boundary")
}

// TestLimitEnforcement verifies blocking occurs exactly at configured limit.
func (s *PostgresStoreSuite) TestLimitEnforcement() {
	ctx := context.Background()
	cfg := &config.GlobalLimit{
		GlobalPerSecond:    10,
		PerInstancePerHour: 1000,
	}
	store := globalthrottle.NewPostgres(s.postgres.DB, cfg)

	// Increment up to limit
	for i := 0; i < cfg.GlobalPerSecond; i++ {
		count, blocked, err := store.IncrementGlobal(ctx)
		s.Require().NoError(err)
		s.False(blocked, "request %d should not be blocked", i+1)
		s.Equal(i+1, count)
	}

	// Next request should be blocked
	_, blocked, err := store.IncrementGlobal(ctx)
	s.Require().NoError(err)
	s.True(blocked, "request at limit+1 should be blocked")
}

// TestHourlyLimitEnforcement verifies the hourly limit works.
func (s *PostgresStoreSuite) TestHourlyLimitEnforcement() {
	ctx := context.Background()
	cfg := &config.GlobalLimit{
		GlobalPerSecond:    1000, // High per-second to not interfere
		PerInstancePerHour: 10,   // Low hourly limit
	}
	store := globalthrottle.NewPostgres(s.postgres.DB, cfg)

	// Increment up to hourly limit
	for i := 0; i < cfg.PerInstancePerHour; i++ {
		_, blocked, err := store.IncrementGlobal(ctx)
		s.Require().NoError(err)
		s.False(blocked, "request %d should not be blocked", i+1)
	}

	// Next request should be blocked by hourly limit
	_, blocked, err := store.IncrementGlobal(ctx)
	s.Require().NoError(err)
	s.True(blocked, "should be blocked by hourly limit")
}

// TestGetGlobalCount verifies count retrieval.
func (s *PostgresStoreSuite) TestGetGlobalCount() {
	ctx := context.Background()
	cfg := &config.GlobalLimit{
		GlobalPerSecond:    100,
		PerInstancePerHour: 1000,
	}
	store := globalthrottle.NewPostgres(s.postgres.DB, cfg)

	// Initially should be 0
	count, err := store.GetGlobalCount(ctx)
	s.Require().NoError(err)
	s.Equal(0, count)

	// Increment several times
	for i := 0; i < 5; i++ {
		_, _, err := store.IncrementGlobal(ctx)
		s.Require().NoError(err)
	}

	count, err = store.GetGlobalCount(ctx)
	s.Require().NoError(err)
	s.Equal(5, count)
}

// TestConcurrentWithDifferentLimits verifies multiple configs don't interfere.
func (s *PostgresStoreSuite) TestConcurrentWithDifferentLimits() {
	// Use a fixed time to prevent bucket reset if test crosses second boundary
	fixedTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	ctx := requestcontext.WithTime(context.Background(), fixedTime)

	cfg := &config.GlobalLimit{
		GlobalPerSecond:    50,
		PerInstancePerHour: 1000,
	}
	store := globalthrottle.NewPostgres(s.postgres.DB, cfg)

	const goroutines = 100
	var wg sync.WaitGroup
	var allowed atomic.Int32

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			_, blocked, err := store.IncrementGlobal(ctx)
			if err == nil && !blocked {
				allowed.Add(1)
			}
		}()
	}

	wg.Wait()

	// Should allow exactly limit requests
	s.Equal(int32(cfg.GlobalPerSecond), allowed.Load())
}
