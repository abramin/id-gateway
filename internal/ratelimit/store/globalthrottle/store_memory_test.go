package globalthrottle

import (
	"context"
	"credo/pkg/requestcontext"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// =============================================================================
// Global Throttle Store Test Suite
// =============================================================================
// Justification: These tests validate the tumbling window algorithm invariants
// that cannot be reliably tested via E2E due to timing sensitivity.
// Invariants tested:
// - Per-second counter resets on second boundary
// - Per-hour counter resets on hour boundary
// - Blocking occurs when limits exceeded
// - Blocked requests don't increment counters (decrement behavior)

type GlobalThrottleStoreSuite struct {
	suite.Suite
	store    *InMemoryGlobalThrottleStore
	baseTime time.Time
}

func TestGlobalThrottleStoreSuite(t *testing.T) {
	suite.Run(t, new(GlobalThrottleStoreSuite))
}

func (s *GlobalThrottleStoreSuite) SetupTest() {
	s.store = New(WithPerSecondLimit(5), WithPerHourLimit(10))
	// Use a fixed time for reproducible tests
	s.baseTime = time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
}

// =============================================================================
// Basic Operations
// =============================================================================

func (s *GlobalThrottleStoreSuite) TestInitialCountIsZero() {
	ctx := requestcontext.WithTime(context.Background(), s.baseTime)

	count, err := s.store.GetGlobalCount(ctx)
	s.Require().NoError(err)
	s.Equal(0, count)
}

func (s *GlobalThrottleStoreSuite) TestIncrementReturnsNewCount() {
	ctx := requestcontext.WithTime(context.Background(), s.baseTime)

	count, blocked, err := s.store.IncrementGlobal(ctx)
	s.Require().NoError(err)
	s.False(blocked)
	s.Equal(1, count)

	count, blocked, err = s.store.IncrementGlobal(ctx)
	s.Require().NoError(err)
	s.False(blocked)
	s.Equal(2, count)
}

// =============================================================================
// Per-Second Window Boundary Tests
// =============================================================================
// Invariant: Counter resets when request arrives in a new second bucket

func (s *GlobalThrottleStoreSuite) TestPerSecondWindowResets() {
	ctx1 := requestcontext.WithTime(context.Background(), s.baseTime)

	// Fill up to limit
	for i := 0; i < 5; i++ {
		_, blocked, err := s.store.IncrementGlobal(ctx1)
		s.Require().NoError(err)
		s.False(blocked, "should not block within limit")
	}

	// Verify at limit
	count, err := s.store.GetGlobalCount(ctx1)
	s.Require().NoError(err)
	s.Equal(5, count)

	// Move to next second - counter should reset
	ctx2 := requestcontext.WithTime(context.Background(), s.baseTime.Add(1*time.Second))

	count, err = s.store.GetGlobalCount(ctx2)
	s.Require().NoError(err)
	s.Equal(0, count, "count should reset on new second boundary")

	// New requests should succeed
	count, blocked, err := s.store.IncrementGlobal(ctx2)
	s.Require().NoError(err)
	s.False(blocked)
	s.Equal(1, count)
}

func (s *GlobalThrottleStoreSuite) TestPerSecondLimitBlocks() {
	ctx := requestcontext.WithTime(context.Background(), s.baseTime)

	// Fill up to limit
	for i := 0; i < 5; i++ {
		_, blocked, err := s.store.IncrementGlobal(ctx)
		s.Require().NoError(err)
		s.False(blocked)
	}

	// Next request should be blocked
	count, blocked, err := s.store.IncrementGlobal(ctx)
	s.Require().NoError(err)
	s.True(blocked, "should block when per-second limit exceeded")
	s.Equal(5, count, "count should remain at limit (blocked request not counted)")
}

// =============================================================================
// Per-Hour Window Boundary Tests
// =============================================================================
// Invariant: Hour counter resets when request arrives in a new hour bucket

func (s *GlobalThrottleStoreSuite) TestPerHourWindowResets() {
	store := New(WithPerSecondLimit(100), WithPerHourLimit(5))

	// Fill up to hour limit across multiple seconds
	for i := 0; i < 5; i++ {
		ctxSecond := requestcontext.WithTime(context.Background(), s.baseTime.Add(time.Duration(i)*time.Second))
		_, blocked, err := store.IncrementGlobal(ctxSecond)
		s.Require().NoError(err)
		s.False(blocked)
	}

	// Next request in same hour should be blocked
	ctx2 := requestcontext.WithTime(context.Background(), s.baseTime.Add(10*time.Second))
	_, blocked, err := store.IncrementGlobal(ctx2)
	s.Require().NoError(err)
	s.True(blocked, "should block when per-hour limit exceeded")

	// Move to next hour - counter should reset
	ctx3 := requestcontext.WithTime(context.Background(), s.baseTime.Add(1*time.Hour))
	count, blocked, err := store.IncrementGlobal(ctx3)
	s.Require().NoError(err)
	s.False(blocked, "should allow after hour boundary")
	s.Equal(1, count)
}

func (s *GlobalThrottleStoreSuite) TestPerHourLimitBlocksEvenWithSecondReset() {
	store := New(WithPerSecondLimit(100), WithPerHourLimit(5))

	// Use requests spread across seconds within same hour
	for i := 0; i < 5; i++ {
		ctx := requestcontext.WithTime(context.Background(), s.baseTime.Add(time.Duration(i)*time.Second))
		_, blocked, err := store.IncrementGlobal(ctx)
		s.Require().NoError(err)
		s.False(blocked)
	}

	// Even though per-second resets, hour limit should still block
	ctx := requestcontext.WithTime(context.Background(), s.baseTime.Add(30*time.Second))
	_, blocked, err := store.IncrementGlobal(ctx)
	s.Require().NoError(err)
	s.True(blocked, "per-hour limit should block even after per-second window reset")
}

// =============================================================================
// Blocked Request Counter Behavior
// =============================================================================
// Invariant: Blocked requests decrement counters to avoid counting them

func (s *GlobalThrottleStoreSuite) TestBlockedRequestNotCounted() {
	ctx := requestcontext.WithTime(context.Background(), s.baseTime)

	// Fill to limit
	for i := 0; i < 5; i++ {
		s.store.IncrementGlobal(ctx)
	}

	// Attempt blocked request
	count1, blocked, _ := s.store.IncrementGlobal(ctx)
	s.True(blocked)

	// Verify count didn't increase
	count2, _ := s.store.GetGlobalCount(ctx)
	s.Equal(count1, count2, "blocked request should not increment count")
	s.Equal(5, count2, "count should remain at limit")
}

// =============================================================================
// Stats Method
// =============================================================================

func (s *GlobalThrottleStoreSuite) TestStatsReturnsCurrentState() {
	ctx := requestcontext.WithTime(context.Background(), s.baseTime)

	// Make some requests
	for i := 0; i < 3; i++ {
		s.store.IncrementGlobal(ctx)
	}

	secCount, hourCount, secBucket, hourBucket := s.store.Stats()

	s.Equal(int64(3), secCount)
	s.Equal(int64(3), hourCount)
	s.Equal(s.baseTime.Unix(), secBucket)
	s.Equal(s.baseTime.Truncate(time.Hour).Unix(), hourBucket)
}

// =============================================================================
// Concurrent Access
// =============================================================================
// Invariant: Atomic operations prevent data races

func (s *GlobalThrottleStoreSuite) TestConcurrentAccess() {
	store := New(WithPerSecondLimit(1000), WithPerHourLimit(10000))
	ctx := requestcontext.WithTime(context.Background(), s.baseTime)

	var wg sync.WaitGroup
	numGoroutines := 100
	requestsPerGoroutine := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < requestsPerGoroutine; j++ {
				store.IncrementGlobal(ctx)
			}
		}()
	}

	wg.Wait()

	count, err := store.GetGlobalCount(ctx)
	s.Require().NoError(err)
	s.Equal(numGoroutines*requestsPerGoroutine, count,
		"all requests should be counted under concurrent access")
}

// =============================================================================
// Default Limits
// =============================================================================

func (s *GlobalThrottleStoreSuite) TestDefaultLimits() {
	store := New() // No options - use defaults
	ctx := requestcontext.WithTime(context.Background(), s.baseTime)

	// Should allow up to 1000 requests per second (default)
	for i := 0; i < 1000; i++ {
		_, blocked, err := store.IncrementGlobal(ctx)
		s.Require().NoError(err)
		s.False(blocked, "should allow up to default per-second limit")
	}

	// 1001st should be blocked
	_, blocked, err := store.IncrementGlobal(ctx)
	s.Require().NoError(err)
	s.True(blocked, "should block beyond default per-second limit")
}
