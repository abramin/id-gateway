package globalthrottle

import (
	"context"
	"sync"
	"time"
)

// InMemoryGlobalThrottleStore implements global rate limiting with sliding windows.
// It tracks both per-second and per-hour limits (PRD-017 FR-6).
type InMemoryGlobalThrottleStore struct {
	mu sync.Mutex

	// Per-second tracking (sliding window)
	secondWindow    []time.Time
	perSecondLimit  int
	secondDuration  time.Duration

	// Per-hour tracking (sliding window)
	hourWindow     []time.Time
	perHourLimit   int
	hourDuration   time.Duration
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
		secondWindow:   make([]time.Time, 0),
		perSecondLimit: 1000,          // Default: 1000 req/sec per instance
		secondDuration: time.Second,
		hourWindow:     make([]time.Time, 0),
		perHourLimit:   100000,        // Default: 100k req/hour per instance
		hourDuration:   time.Hour,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// IncrementGlobal increments the global counter and checks if the request is blocked.
// Returns blocked=true if either per-second or per-hour limit is exceeded.
func (s *InMemoryGlobalThrottleStore) IncrementGlobal(_ context.Context) (count int, blocked bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Clean up and check per-second window
	s.secondWindow = s.cleanWindow(s.secondWindow, now, s.secondDuration)
	if len(s.secondWindow) >= s.perSecondLimit {
		return len(s.secondWindow), true, nil
	}

	// Clean up and check per-hour window
	s.hourWindow = s.cleanWindow(s.hourWindow, now, s.hourDuration)
	if len(s.hourWindow) >= s.perHourLimit {
		return len(s.hourWindow), true, nil
	}

	// Add current request to both windows
	s.secondWindow = append(s.secondWindow, now)
	s.hourWindow = append(s.hourWindow, now)

	return len(s.secondWindow), false, nil
}

// GetGlobalCount returns the current count in the per-second window.
func (s *InMemoryGlobalThrottleStore) GetGlobalCount(_ context.Context) (count int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.secondWindow = s.cleanWindow(s.secondWindow, now, s.secondDuration)
	return len(s.secondWindow), nil
}

// cleanWindow removes timestamps older than the window duration.
func (s *InMemoryGlobalThrottleStore) cleanWindow(window []time.Time, now time.Time, duration time.Duration) []time.Time {
	cutoff := now.Add(-duration)

	// Find the first timestamp within the window
	idx := 0
	for idx < len(window) && window[idx].Before(cutoff) {
		idx++
	}

	if idx == 0 {
		return window
	}

	// Return slice starting from first valid timestamp
	return window[idx:]
}
