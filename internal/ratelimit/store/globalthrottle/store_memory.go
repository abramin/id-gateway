package globalthrottle

import (
	"context"
	"sync/atomic"
	"time"
)

// InMemoryGlobalThrottleStore implements global rate limiting with atomic counters.
// Uses tumbling windows (per-second and per-hour) for lock-free operation.
// This provides approximate rate limiting with minimal contention.
type InMemoryGlobalThrottleStore struct {
	// Per-second tracking (tumbling window)
	secondCount  atomic.Int64
	secondBucket atomic.Int64 // Unix timestamp of current second bucket
	perSecondLimit int

	// Per-hour tracking (tumbling window)
	hourCount  atomic.Int64
	hourBucket atomic.Int64 // Unix timestamp of current hour bucket (truncated to hour)
	perHourLimit int
}

// Option configures the store.
type Option func(*InMemoryGlobalThrottleStore)

// WithPerSecondLimit sets the per-second limit.
func WithPerSecondLimit(limit int) Option {
	return func(s *InMemoryGlobalThrottleStore) {
		s.perSecondLimit = limit
	}
}

// WithPerHourLimit sets the per-hour limit.
func WithPerHourLimit(limit int) Option {
	return func(s *InMemoryGlobalThrottleStore) {
		s.perHourLimit = limit
	}
}

// New creates a new global throttle store with default limits.
func New(opts ...Option) *InMemoryGlobalThrottleStore {
	s := &InMemoryGlobalThrottleStore{
		perSecondLimit: 1000,   // Default: 1000 req/sec per instance
		perHourLimit:   100000, // Default: 100k req/hour per instance
	}

	for _, opt := range opts {
		opt(s)
	}
}

	return s
}

// IncrementGlobal increments the global counter and checks if the request is blocked.
// Returns blocked=true if either per-second or per-hour limit is exceeded.
// Uses atomic operations for lock-free concurrency.
func (s *InMemoryGlobalThrottleStore) IncrementGlobal(_ context.Context) (count int, blocked bool, err error) {
	now := time.Now()
	currentSecond := now.Unix()
	currentHour := now.Truncate(time.Hour).Unix()

	// Check and potentially reset per-second counter
	lastSecond := s.secondBucket.Load()
	if currentSecond != lastSecond {
		// Try to claim the new second bucket
		if s.secondBucket.CompareAndSwap(lastSecond, currentSecond) {
			s.secondCount.Store(0)
		}
	}

	// Check and potentially reset per-hour counter
	lastHour := s.hourBucket.Load()
	if currentHour != lastHour {
		// Try to claim the new hour bucket
		if s.hourBucket.CompareAndSwap(lastHour, currentHour) {
			s.hourCount.Store(0)
		}
	}

	// Increment and check per-second limit
	secCount := s.secondCount.Add(1)
	if secCount > int64(s.perSecondLimit) {
		// Over limit - decrement to avoid counting this request
		s.secondCount.Add(-1)
		return int(secCount - 1), true, nil
	}

	// Increment and check per-hour limit
	hourCount := s.hourCount.Add(1)
	if hourCount > int64(s.perHourLimit) {
		// Over limit - decrement both counters
		s.secondCount.Add(-1)
		s.hourCount.Add(-1)
		return int(hourCount - 1), true, nil
	}

	return int(secCount), false, nil
}

// GetGlobalCount returns the current count in the per-second window.
func (s *InMemoryGlobalThrottleStore) GetGlobalCount(_ context.Context) (count int, err error) {
	now := time.Now()
	currentSecond := now.Unix()

	// If we're in a new second, the effective count is 0
	if currentSecond != s.secondBucket.Load() {
		return 0, nil
	}

	return int(s.secondCount.Load()), nil
}

// Stats returns current counters for monitoring.
func (s *InMemoryGlobalThrottleStore) Stats() (secondCount, hourCount int64, secondBucket, hourBucket int64) {
	return s.secondCount.Load(), s.hourCount.Load(), s.secondBucket.Load(), s.hourBucket.Load()
}
