package bucket

import (
	"context"
	"sync"
	"time"

	"credo/internal/ratelimit/models"
)

// InMemoryBucketStore implements BucketStore using in-memory sliding window.
// For production, use RedisStore instead.
type InMemoryBucketStore struct {
	mu      sync.RWMutex
	buckets map[string]*slidingWindow // key.String() -> sliding window
}

// slidingWindow is the aggregate root for rate limit state.
type slidingWindow struct {
	timestamps []time.Time
	window     time.Duration
}

// tryConsume attempts to consume tokens from the sliding window.
// Returns whether the request was allowed, remaining capacity, and reset time.
func (sw *slidingWindow) tryConsume(cost, limit int, now time.Time) (allowed bool, remaining int, resetAt time.Time) {
	sw.cleanupExpired(now)

	if len(sw.timestamps)+cost > limit {
		return false, 0, now.Add(sw.window)
	}

	// Record consumption
	for range cost {
		sw.timestamps = append(sw.timestamps, now)
	}

	return true, limit - len(sw.timestamps), sw.timestamps[0].Add(sw.window)
}

func (sw *slidingWindow) count(now time.Time) int {
	sw.cleanupExpired(now)
	return len(sw.timestamps)
}

func (sw *slidingWindow) cleanupExpired(now time.Time) {
	cutoff := now.Add(-sw.window)
	i := 0
	for ; i < len(sw.timestamps); i++ {
		if sw.timestamps[i].After(cutoff) {
			break
		}
	}
	sw.timestamps = sw.timestamps[i:]
}

// NewInMemoryBucketStore creates a new in-memory bucket store.
func NewInMemoryBucketStore() *InMemoryBucketStore {
	return &InMemoryBucketStore{
		buckets: make(map[string]*slidingWindow),
	}
}

// Allow checks if a request is allowed and increments the counter.
func (s *InMemoryBucketStore) Allow(ctx context.Context, key string, limit int, window time.Duration) (*models.RateLimitResult, error) {
	return s.AllowN(ctx, key, 1, limit, window)
}

// AllowN checks if a request with custom cost is allowed.
func (s *InMemoryBucketStore) AllowN(ctx context.Context, key string, cost, limit int, window time.Duration) (*models.RateLimitResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bucket, ok := s.buckets[key]
	if !ok {
		bucket = &slidingWindow{
			timestamps: []time.Time{},
			window:     window,
		}
		s.buckets[key] = bucket
	}
	allowed, remaining, resetAt := bucket.tryConsume(cost, limit, time.Now())

	return &models.RateLimitResult{
		Allowed:    allowed,
		Limit:      limit,
		Remaining:  remaining,
		ResetAt:    resetAt,
		RetryAfter: retryAfterSeconds(allowed, resetAt),
	}, nil
}

// Reset clears the rate limit counter for a key.
func (s *InMemoryBucketStore) Reset(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.buckets, key)
	return nil
}

// GetCurrentCount returns the current request count for a key.
func (s *InMemoryBucketStore) GetCurrentCount(ctx context.Context, key string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	bucket, ok := s.buckets[key]
	if !ok {
		return 0, nil
	}

	return bucket.count(time.Now()), nil
}

// retryAfterSeconds calculates seconds until retry is allowed.
func retryAfterSeconds(allowed bool, resetAt time.Time) int {
	if allowed {
		return 0
	}
	seconds := int(time.Until(resetAt).Seconds())
	if seconds < 0 {
		return 0
	}
	return seconds
}
