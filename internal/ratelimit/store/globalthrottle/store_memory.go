package globalthrottle

import (
	"context"
	"credo/pkg/requestcontext"
	"sync/atomic"
	"time"
)

// InMemoryGlobalThrottleStore implements global rate limiting with atomic counters.
// Uses tumbling windows (per-second and per-hour) for lock-free operation.
// This provides approximate rate limiting with minimal contention.
type InMemoryGlobalThrottleStore struct {
	// Per-second tracking (tumbling window)
	secondCount    atomic.Int64
	secondBucket   atomic.Int64 // Unix timestamp of current second bucket
	perSecondLimit int

	// Per-hour tracking (tumbling window)
	hourCount    atomic.Int64
	hourBucket   atomic.Int64 // Unix timestamp of current hour bucket (truncated to hour)
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
	return s
}

// IncrementGlobal increments the global counter and checks if the request is blocked.
// Returns blocked=true if either per-second or per-hour limit is exceeded.
// Uses CAS (Compare-And-Swap) operations to ensure the counter never exceeds the limit,
// preventing TOCTOU races where multiple goroutines could temporarily exceed the limit.
func (s *InMemoryGlobalThrottleStore) IncrementGlobal(ctx context.Context) (count int, blocked bool, err error) {
	now := requestcontext.Now(ctx)
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

	// SECURITY: Use CAS to atomically check-and-increment per-second counter.
	// This prevents the counter from ever exceeding the limit, even momentarily,
	// avoiding TOCTOU races where Add(1) followed by comparison could overshoot.
	secCount, secBlocked := s.tryIncrementWithLimit(&s.secondCount, int64(s.perSecondLimit))
	if secBlocked {
		return int(secCount), true, nil
	}

	// CAS-based increment for per-hour counter
	hourCount, hourBlocked := s.tryIncrementWithLimit(&s.hourCount, int64(s.perHourLimit))
	if hourBlocked {
		// Roll back the second counter since we're not allowing this request
		s.secondCount.Add(-1)
		return int(hourCount), true, nil
	}

	return int(secCount), false, nil
}

// tryIncrementWithLimit atomically increments a counter only if it won't exceed the limit.
// Uses CAS loop to ensure the counter never exceeds the limit, even under contention.
// Returns the current count and whether the request was blocked.
func (s *InMemoryGlobalThrottleStore) tryIncrementWithLimit(counter *atomic.Int64, limit int64) (count int64, blocked bool) {
	for {
		current := counter.Load()
		if current >= limit {
			return current, true
		}
		if counter.CompareAndSwap(current, current+1) {
			return current + 1, false
		}
		// CAS failed due to contention, retry
	}
}

// GetGlobalCount returns the current count in the per-second window.
func (s *InMemoryGlobalThrottleStore) GetGlobalCount(ctx context.Context) (count int, err error) {
	now := requestcontext.Now(ctx)
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
