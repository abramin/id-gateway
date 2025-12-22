package bucket

import (
	"context"
	"sync"
	"time"

	"credo/internal/ratelimit/models"
)

// slidingWindow is the aggregate root for rate limit state.
type slidingWindow struct {
	timestamps []time.Time
	window     time.Duration
}

func (sw *slidingWindow) tryConsume(cost, limit int, now time.Time) (allowed bool, remaining int, resetAt time.Time) {
	sw.cleanupExpired(now)

	if len(sw.timestamps)+cost > limit {
		return false, 0, now.Add(sw.window)
	}

	// Record consumption
	for range cost {
		sw.timestamps = append(sw.timestamps, now)
	}

	remaining = limit - len(sw.timestamps)
	resetAt = sw.timestamps[0].Add(sw.window)
	return true, remaining, resetAt
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

// For production, use RedisStore instead.
type InMemoryBucketStore struct {
	mu      sync.RWMutex
	buckets map[string]*slidingWindow // key.String() -> sliding window
}

func New() *InMemoryBucketStore {
	return &InMemoryBucketStore{
		buckets: make(map[string]*slidingWindow),
	}
}

func (s *InMemoryBucketStore) Allow(ctx context.Context, key string, limit int, window time.Duration) (*models.RateLimitResult, error) {
	return s.AllowN(ctx, key, 1, limit, window)
}

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

func (s *InMemoryBucketStore) Reset(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.buckets, key)
	return nil
}

func (s *InMemoryBucketStore) GetCurrentCount(ctx context.Context, key string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	bucket, ok := s.buckets[key]
	if !ok {
		return 0, nil
	}

	return bucket.count(time.Now()), nil
}

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
