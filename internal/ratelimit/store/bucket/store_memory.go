package bucket

import (
	"container/list"
	"context"
	"hash/fnv"
	"sync"
	"time"

	"credo/internal/ratelimit/models"
	requesttime "credo/pkg/platform/middleware/requesttime"
)

const (
	defaultShardCount  = 32
	defaultMaxBuckets  = 100000 // Max buckets per shard before LRU eviction
	circularBufferSize = 256    // Fixed size for circular buffer (covers most limits)

	// maxClockSkewTolerance is the maximum amount of time a timestamp can be
	// in the future before it's rejected. This prevents clock skew attacks
	// where malicious clients could corrupt sliding window state.
	maxClockSkewTolerance = 5 * time.Second
)

// ---------------------------------------------------------------------------
// Sliding Window Rate Limiter
// ---------------------------------------------------------------------------
//
// This implements a sliding window rate limiter using a circular buffer.
//
// How it works:
//   - Each request's timestamp is recorded in a fixed-size circular buffer
//   - To check the limit, we count how many timestamps fall within the window
//   - Expired timestamps (outside the window) are ignored during counting
//
// Example: limit=5 requests per 1-minute window
//
//	Timeline (newest on right):
//	|------ 1 minute window ------|
//	[expired] [expired] [req1] [req2] [req3] [req4] [req5]
//	                    ↑ valid requests = 5, at limit
//
// The circular buffer provides O(1) amortized operations and bounded memory.
// When the buffer fills, old entries are overwritten (they're expired anyway).
// ---------------------------------------------------------------------------

// slidingWindow tracks request timestamps in a circular buffer for rate limiting.
type slidingWindow struct {
	timestamps [circularBufferSize]int64 // Request timestamps as Unix nanoseconds
	writePos   int                       // Next position to write (head of circular buffer)
	size       int                       // Number of entries written (up to buffer capacity)
	windowSize time.Duration             // Duration of the sliding window
}

// tryConsume attempts to record 'cost' requests against the rate limit.
//
// Returns:
//   - allowed: true if the request is within the limit
//   - remaining: number of requests still available in the window
//   - resetAt: when the oldest request expires (allowing new requests)
func (sw *slidingWindow) tryConsume(cost int, limit int, now time.Time) (allowed bool, remaining int, resetAt time.Time) {
	nowNano := now.UnixNano()
	windowStart := nowNano - sw.windowSize.Nanoseconds()

	// Count requests within the current window and find the oldest one
	requestsInWindow, oldestTimestamp := sw.countRequestsInWindow(windowStart, nowNano)

	// Update size to reflect only valid entries (lazy cleanup)
	sw.size = requestsInWindow

	// Check if adding these requests would exceed the limit
	if requestsInWindow+cost > limit {
		// Calculate when the oldest request will expire
		oldestExpiry := time.Unix(0, oldestTimestamp).Add(sw.windowSize)
		return false, 0, oldestExpiry
	}

	// Record the new request timestamps
	sw.recordRequests(cost, nowNano, nowNano)

	remaining = limit - (requestsInWindow + cost)
	resetAt = now.Add(sw.windowSize)
	return true, remaining, resetAt
}

// countRequestsInWindow counts valid requests and finds the oldest timestamp.
// Timestamps more than maxClockSkewTolerance in the future are ignored to prevent
// clock skew attacks from corrupting the sliding window state.
func (sw *slidingWindow) countRequestsInWindow(windowStart, nowNano int64) (count int, oldestTimestamp int64) {
	oldestTimestamp = nowNano // Default to now if no valid requests
	maxValidTimestamp := nowNano + maxClockSkewTolerance.Nanoseconds()

	for i := 0; i < sw.size; i++ {
		idx := sw.bufferIndex(i)
		ts := sw.timestamps[idx]

		// Skip timestamps outside the window or too far in the future (clock skew protection)
		if ts > windowStart && ts <= maxValidTimestamp {
			count++
			if ts < oldestTimestamp {
				oldestTimestamp = ts
			}
		}
	}
	return count, oldestTimestamp
}

// bufferIndex calculates the actual array index for a logical position.
// Position 0 is the oldest entry, position (size-1) is the newest.
func (sw *slidingWindow) bufferIndex(position int) int {
	return (sw.writePos - sw.size + position + circularBufferSize) % circularBufferSize
}

// recordRequests writes 'count' request timestamps to the buffer.
// Timestamps are clamped to at most maxClockSkewTolerance in the future
// to prevent clock skew attacks from corrupting the sliding window.
func (sw *slidingWindow) recordRequests(count int, timestamp int64, nowNano int64) {
	// Clamp timestamp to prevent clock skew attacks
	maxValidTimestamp := nowNano + maxClockSkewTolerance.Nanoseconds()
	if timestamp > maxValidTimestamp {
		timestamp = maxValidTimestamp
	}

	for range count {
		sw.timestamps[sw.writePos] = timestamp
		sw.writePos = (sw.writePos + 1) % circularBufferSize

		if sw.size < circularBufferSize {
			sw.size++
		}
		// When size == circularBufferSize, we're overwriting old entries
		// This is fine because they're expired anyway
	}
}

// currentCount returns the number of requests currently in the window.
func (sw *slidingWindow) currentCount(now time.Time) int {
	windowStart := now.UnixNano() - sw.windowSize.Nanoseconds()
	count, _ := sw.countRequestsInWindow(windowStart, now.UnixNano())
	return count
}

// lruEntry wraps a sliding window with LRU tracking.
type lruEntry struct {
	key    string
	window *slidingWindow
}

// shard is a partition of the bucket store with its own lock and LRU list.
type shard struct {
	mu      sync.RWMutex
	buckets map[string]*list.Element
	lruList *list.List
	maxSize int
}

func newShard(maxSize int) *shard {
	return &shard{
		buckets: make(map[string]*list.Element),
		lruList: list.New(),
		maxSize: maxSize,
	}
}

func (s *shard) get(key string) (*slidingWindow, bool) {
	elem, ok := s.buckets[key]
	if !ok {
		return nil, false
	}
	// Move to front (most recently used)
	s.lruList.MoveToFront(elem)
	return elem.Value.(*lruEntry).window, true
}

func (s *shard) set(key string, window *slidingWindow) {
	if elem, ok := s.buckets[key]; ok {
		s.lruList.MoveToFront(elem)
		elem.Value.(*lruEntry).window = window
		return
	}

	// Evict if at capacity
	if s.lruList.Len() >= s.maxSize {
		oldest := s.lruList.Back()
		if oldest != nil {
			entry := oldest.Value.(*lruEntry)
			delete(s.buckets, entry.key)
			s.lruList.Remove(oldest)
		}
	}

	entry := &lruEntry{key: key, window: window}
	// Insert new entry at front
	elem := s.lruList.PushFront(entry)
	s.buckets[key] = elem
}

func (s *shard) delete(key string) {
	if elem, ok := s.buckets[key]; ok {
		s.lruList.Remove(elem)
		delete(s.buckets, key)
	}
}

// InMemoryBucketStore implements a sharded, LRU-evicting rate limit store
// with circular buffer sliding windows for bounded memory and O(1) operations.
// For production at scale, use RedisStore instead.
type InMemoryBucketStore struct {
	shards     []*shard
	shardCount uint32
}

// Option configures the bucket store.
type Option func(*InMemoryBucketStore)

// WithShardCount sets the number of shards (default 32).
func WithShardCount(count int) Option {
	return func(s *InMemoryBucketStore) {
		if count > 0 {
			s.shardCount = uint32(count)
		}
	}
}

// WithMaxBucketsPerShard sets max buckets per shard before LRU eviction.
func WithMaxBucketsPerShard(max int) Option {
	return func(s *InMemoryBucketStore) {
		for _, sh := range s.shards {
			sh.maxSize = max
		}
	}
}

func New(opts ...Option) *InMemoryBucketStore {
	store := &InMemoryBucketStore{
		shardCount: defaultShardCount,
	}

	// Apply options that affect shard count first
	for _, opt := range opts {
		opt(store)
	}

	// Initialize shards
	store.shards = make([]*shard, store.shardCount)
	for i := range store.shards {
		store.shards[i] = newShard(defaultMaxBuckets)
	}

	// Apply remaining options
	for _, opt := range opts {
		opt(store)
	}

	return store
}

func (s *InMemoryBucketStore) getShard(key string) *shard {
	h := fnv.New32a()
	h.Write([]byte(key))
	return s.shards[h.Sum32()%s.shardCount]
}

func (s *InMemoryBucketStore) Allow(ctx context.Context, key string, limit int, window time.Duration) (*models.RateLimitResult, error) {
	return s.AllowN(ctx, key, 1, limit, window)
}

func (s *InMemoryBucketStore) AllowN(ctx context.Context, key string, cost, limit int, windowDuration time.Duration) (*models.RateLimitResult, error) {
	sh := s.getShard(key)

	sh.mu.Lock()
	defer sh.mu.Unlock()

	sw, ok := sh.get(key)
	if !ok {
		sw = &slidingWindow{
			windowSize: windowDuration,
		}
		sh.set(key, sw)
	}

	now := requesttime.Now(ctx)
	allowed, remaining, resetAt := sw.tryConsume(cost, limit, now)

	return &models.RateLimitResult{
		Allowed:    allowed,
		Limit:      limit,
		Remaining:  remaining,
		ResetAt:    resetAt,
		RetryAfter: retryAfterSeconds(allowed, resetAt, now),
	}, nil
}

func (s *InMemoryBucketStore) Reset(ctx context.Context, key string) error {
	sh := s.getShard(key)

	sh.mu.Lock()
	defer sh.mu.Unlock()

	sh.delete(key)
	return nil
}

func (s *InMemoryBucketStore) GetCurrentCount(ctx context.Context, key string) (int, error) {
	sh := s.getShard(key)

	sh.mu.RLock()
	defer sh.mu.RUnlock()

	elem, ok := sh.buckets[key]
	if !ok {
		return 0, nil
	}

	return elem.Value.(*lruEntry).window.currentCount(requesttime.Now(ctx)), nil
}

// Stats returns store statistics for monitoring.
func (s *InMemoryBucketStore) Stats() (totalBuckets int, bucketsPerShard []int) {
	bucketsPerShard = make([]int, s.shardCount)
	for i, sh := range s.shards {
		sh.mu.RLock()
		bucketsPerShard[i] = len(sh.buckets)
		totalBuckets += bucketsPerShard[i]
		sh.mu.RUnlock()
	}
	return
}

func retryAfterSeconds(allowed bool, resetAt, now time.Time) int {
	if allowed {
		return 0
	}
	seconds := int(resetAt.Sub(now).Seconds())
	if seconds < 0 {
		return 0
	}
	return seconds
}
