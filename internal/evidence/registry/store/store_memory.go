package store

import (
	"context"
	"errors"
	"sync"
	"time"

	"credo/internal/evidence/registry/metrics"
	"credo/internal/evidence/registry/models"
	id "credo/pkg/domain"
)

// Default cache configuration
const (
	DefaultMaxCacheSize = 10000 // Maximum entries per cache type
)

type cachedCitizen struct {
	record     models.CitizenRecord
	storedAt   time.Time
	lastAccess time.Time
	regulated  bool // Track whether this record was stored in minimized (regulated) mode
}

type cachedSanction struct {
	record     models.SanctionsRecord
	storedAt   time.Time
	lastAccess time.Time
}

// InMemoryCache provides an in-memory cache for registry records with TTL expiration
// and LRU eviction. Citizen records track their regulated mode to prevent serving
// stale PII when the system switches between regulated and non-regulated modes.
//
// The cache has separate locks for citizens and sanctions to reduce contention.
// Expired entries are cleaned up lazily on access and periodically via background cleanup.
type InMemoryCache struct {
	citizenMu  sync.RWMutex
	sanctionMu sync.RWMutex
	citizens   map[string]cachedCitizen
	sanctions  map[string]cachedSanction
	cacheTTL   time.Duration
	maxSize    int
	metrics    *metrics.Metrics
}

// ErrNotFound is returned when a requested record does not exist in the cache.
var ErrNotFound = errors.New("not found")

// CacheOption configures the InMemoryCache.
type CacheOption func(*InMemoryCache)

// WithMaxSize sets the maximum number of entries per cache type.
func WithMaxSize(size int) CacheOption {
	return func(c *InMemoryCache) {
		c.maxSize = size
	}
}

// WithMetrics enables Prometheus metrics collection for cache operations.
func WithMetrics(m *metrics.Metrics) CacheOption {
	return func(c *InMemoryCache) {
		c.metrics = m
	}
}

// NewInMemoryCache creates a new in-memory cache with the specified TTL.
func NewInMemoryCache(cacheTTL time.Duration, opts ...CacheOption) *InMemoryCache {
	c := &InMemoryCache{
		citizens:  make(map[string]cachedCitizen),
		sanctions: make(map[string]cachedSanction),
		cacheTTL:  cacheTTL,
		maxSize:   DefaultMaxCacheSize,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// SaveCitizen stores a citizen record in the cache.
// The key parameter is the original lookup key (national ID), used to avoid cache
// collisions when records are minimized (regulated mode blanks NationalID in record).
// The regulated parameter indicates whether the record is in minimized form.
// If record is nil, the operation is a no-op and returns nil.
func (c *InMemoryCache) SaveCitizen(_ context.Context, key id.NationalID, record *models.CitizenRecord, regulated bool) error {
	if record == nil {
		return nil
	}
	if key.IsNil() {
		return errors.New("cannot cache citizen record with nil key")
	}

	c.citizenMu.Lock()
	defer c.citizenMu.Unlock()

	// Evict oldest entry if at capacity
	if len(c.citizens) >= c.maxSize {
		c.evictOldestCitizenLocked()
	}

	now := time.Now()
	c.citizens[key.String()] = cachedCitizen{
		record:     *record,
		storedAt:   now,
		lastAccess: now,
		regulated:  regulated,
	}
	return nil
}

// FindCitizen retrieves a cached citizen record by national ID.
// Returns ErrNotFound if:
//   - The record does not exist
//   - The record has expired past the cache TTL
//   - The stored regulated mode doesn't match the requested mode (prevents stale PII)
func (c *InMemoryCache) FindCitizen(_ context.Context, nationalID id.NationalID, regulated bool) (*models.CitizenRecord, error) {
	start := time.Now()

	c.citizenMu.Lock()
	defer c.citizenMu.Unlock()

	cached, ok := c.citizens[nationalID.String()]
	if !ok {
		c.recordMiss("citizen", start)
		return nil, ErrNotFound
	}

	// Check TTL expiration
	if time.Since(cached.storedAt) >= c.cacheTTL {
		// Lazy cleanup: remove expired entry
		delete(c.citizens, nationalID.String())
		c.recordMiss("citizen", start)
		return nil, ErrNotFound
	}

	// Cache miss if regulated mode changed - prevents serving stale PII
	if cached.regulated != regulated {
		c.recordMiss("citizen", start)
		return nil, ErrNotFound
	}

	// Update last access time for LRU
	cached.lastAccess = time.Now()
	c.citizens[nationalID.String()] = cached

	c.recordHit("citizen", start)
	return &cached.record, nil
}

// SaveSanction stores a sanctions record in the cache.
// The key parameter is the original lookup key (national ID).
// If record is nil, the operation is a no-op and returns nil.
func (c *InMemoryCache) SaveSanction(_ context.Context, key id.NationalID, record *models.SanctionsRecord) error {
	if record == nil {
		return nil
	}
	if key.IsNil() {
		return errors.New("cannot cache sanction record with nil key")
	}

	c.sanctionMu.Lock()
	defer c.sanctionMu.Unlock()

	// Evict oldest entry if at capacity
	if len(c.sanctions) >= c.maxSize {
		c.evictOldestSanctionLocked()
	}

	now := time.Now()
	c.sanctions[key.String()] = cachedSanction{
		record:     *record,
		storedAt:   now,
		lastAccess: now,
	}
	return nil
}

// FindSanction retrieves a cached sanctions record by national ID.
// Returns ErrNotFound if the record does not exist or has expired past the cache TTL.
func (c *InMemoryCache) FindSanction(_ context.Context, nationalID id.NationalID) (*models.SanctionsRecord, error) {
	start := time.Now()

	c.sanctionMu.Lock()
	defer c.sanctionMu.Unlock()

	cached, ok := c.sanctions[nationalID.String()]
	if !ok {
		c.recordMiss("sanctions", start)
		return nil, ErrNotFound
	}

	// Check TTL expiration
	if time.Since(cached.storedAt) >= c.cacheTTL {
		// Lazy cleanup: remove expired entry
		delete(c.sanctions, nationalID.String())
		c.recordMiss("sanctions", start)
		return nil, ErrNotFound
	}

	// Update last access time for LRU
	cached.lastAccess = time.Now()
	c.sanctions[nationalID.String()] = cached

	c.recordHit("sanctions", start)
	return &cached.record, nil
}

// evictOldestCitizenLocked removes the least recently accessed citizen entry.
// Must be called with citizenMu held.
func (c *InMemoryCache) evictOldestCitizenLocked() {
	var oldestKey string
	var oldestTime time.Time

	for key, cached := range c.citizens {
		if oldestKey == "" || cached.lastAccess.Before(oldestTime) {
			oldestKey = key
			oldestTime = cached.lastAccess
		}
	}

	if oldestKey != "" {
		delete(c.citizens, oldestKey)
	}
}

// evictOldestSanctionLocked removes the least recently accessed sanction entry.
// Must be called with sanctionMu held.
func (c *InMemoryCache) evictOldestSanctionLocked() {
	var oldestKey string
	var oldestTime time.Time

	for key, cached := range c.sanctions {
		if oldestKey == "" || cached.lastAccess.Before(oldestTime) {
			oldestKey = key
			oldestTime = cached.lastAccess
		}
	}

	if oldestKey != "" {
		delete(c.sanctions, oldestKey)
	}
}

// CleanupExpired removes all expired entries from both caches.
// This can be called periodically by a background goroutine.
func (c *InMemoryCache) CleanupExpired() {
	now := time.Now()

	c.citizenMu.Lock()
	for key, cached := range c.citizens {
		if now.Sub(cached.storedAt) >= c.cacheTTL {
			delete(c.citizens, key)
		}
	}
	c.citizenMu.Unlock()

	c.sanctionMu.Lock()
	for key, cached := range c.sanctions {
		if now.Sub(cached.storedAt) >= c.cacheTTL {
			delete(c.sanctions, key)
		}
	}
	c.sanctionMu.Unlock()
}

// Size returns the current number of entries in each cache.
func (c *InMemoryCache) Size() (citizens, sanctions int) {
	c.citizenMu.RLock()
	citizens = len(c.citizens)
	c.citizenMu.RUnlock()

	c.sanctionMu.RLock()
	sanctions = len(c.sanctions)
	c.sanctionMu.RUnlock()

	return citizens, sanctions
}

// ClearAll removes all entries from both caches.
// This is used for cache invalidation, such as when regulated mode changes.
func (c *InMemoryCache) ClearAll() {
	c.citizenMu.Lock()
	c.citizens = make(map[string]cachedCitizen)
	c.citizenMu.Unlock()

	c.sanctionMu.Lock()
	c.sanctions = make(map[string]cachedSanction)
	c.sanctionMu.Unlock()

	if c.metrics != nil {
		c.metrics.IncrementInvalidations()
	}
}

// recordHit records a cache hit metric if metrics are enabled.
func (c *InMemoryCache) recordHit(recordType string, start time.Time) {
	if c.metrics == nil {
		return
	}
	c.metrics.RecordCacheHit(recordType)
	c.metrics.ObserveLookupDuration(recordType, time.Since(start).Seconds())
}

// recordMiss records a cache miss metric if metrics are enabled.
func (c *InMemoryCache) recordMiss(recordType string, start time.Time) {
	if c.metrics == nil {
		return
	}
	c.metrics.RecordCacheMiss(recordType)
	c.metrics.ObserveLookupDuration(recordType, time.Since(start).Seconds())
}
