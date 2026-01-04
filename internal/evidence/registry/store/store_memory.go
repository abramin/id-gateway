/*
Package store provides an in-memory LRU cache for registry records.

# LRU Cache Implementation

This cache uses the classic O(1) LRU (Least Recently Used) algorithm combining
a hash map with a doubly-linked list. This design ensures constant-time complexity
for all cache operations: lookup, insert, update, and eviction.

# Data Structures

The cache maintains two synchronized data structures:

 1. Hash Map (map[string]*list.Element)
    - Provides O(1) key lookup
    - Values are pointers to list elements (not the cached data directly)

 2. Doubly-Linked List (container/list)
    - Maintains access order: front = most recent, back = least recent
    - Enables O(1) reordering and eviction

# Visual Representation

	┌─────────────────────────────────────────────────────────────────┐
	│                         Hash Map                                │
	│  ┌─────────┬─────────┬─────────┬─────────┬─────────┐           │
	│  │ key: A  │ key: B  │ key: C  │ key: D  │ key: E  │           │
	│  │  ↓      │  ↓      │  ↓      │  ↓      │  ↓      │           │
	│  │ elem*   │ elem*   │ elem*   │ elem*   │ elem*   │           │
	│  └────┼────┴────┼────┴────┼────┴────┼────┴────┼────┘           │
	└───────┼─────────┼─────────┼─────────┼─────────┼─────────────────┘
	        │         │         │         │         │
	        ▼         ▼         ▼         ▼         ▼
	┌─────────────────────────────────────────────────────────────────┐
	│                    Doubly-Linked List                           │
	│                                                                 │
	│   FRONT (MRU)                                    BACK (LRU)     │
	│      │                                              │           │
	│      ▼                                              ▼           │
	│   ┌──────┐    ┌──────┐    ┌──────┐    ┌──────┐    ┌──────┐     │
	│   │  A   │◄──►│  B   │◄──►│  C   │◄──►│  D   │◄──►│  E   │     │
	│   │ data │    │ data │    │ data │    │ data │    │ data │     │
	│   └──────┘    └──────┘    └──────┘    └──────┘    └──────┘     │
	│                                                     ▲           │
	│                                          Evict this first       │
	└─────────────────────────────────────────────────────────────────┘

# Operations and Complexity

	┌────────────┬────────────┬─────────────────────────────────────────────┐
	│ Operation  │ Complexity │ Description                                 │
	├────────────┼────────────┼─────────────────────────────────────────────┤
	│ Find/Get   │ O(1)       │ Map lookup + MoveToFront                    │
	│ Save/Put   │ O(1)       │ Map insert + PushFront (or update existing) │
	│ Evict      │ O(1)       │ Remove from Back + delete from map          │
	│ Delete     │ O(1)       │ Map lookup + Remove from list               │
	└────────────┴────────────┴─────────────────────────────────────────────┘

# Cache Access Flow

	┌─────────────────────────────────────────────────────────────────┐
	│                        Find(key)                                │
	└─────────────────────────────────────────────────────────────────┘
	                              │
	                              ▼
	               ┌──────────────────────────────┐
	               │  Map lookup: citizens[key]   │
	               └──────────────────────────────┘
	                              │
	              ┌───────────────┴───────────────┐
	              │                               │
	         key found                       key not found
	              │                               │
	              ▼                               ▼
	    ┌─────────────────┐              ┌─────────────────┐
	    │ Check TTL       │              │ Return ErrNotFound│
	    └─────────────────┘              └─────────────────┘
	              │
	       ┌──────┴──────┐
	       │             │
	   not expired    expired
	       │             │
	       ▼             ▼
	┌─────────────┐  ┌─────────────────────────────┐
	│MoveToFront  │  │ Lazy cleanup:               │
	│Return record│  │  - Remove from list         │
	└─────────────┘  │  - Delete from map          │
	                 │  - Return ErrNotFound       │
	                 └─────────────────────────────┘

# Cache Insert Flow

	┌─────────────────────────────────────────────────────────────────┐
	│                       Save(key, record)                         │
	└─────────────────────────────────────────────────────────────────┘
	                              │
	                              ▼
	               ┌──────────────────────────────┐
	               │  Map lookup: citizens[key]   │
	               └──────────────────────────────┘
	                              │
	              ┌───────────────┴───────────────┐
	              │                               │
	         key exists                      key is new
	              │                               │
	              ▼                               ▼
	    ┌─────────────────┐              ┌─────────────────────────┐
	    │ Update value    │              │ Check capacity          │
	    │ MoveToFront     │              └─────────────────────────┘
	    └─────────────────┘                        │
	                                    ┌──────────┴──────────┐
	                                    │                     │
	                               at capacity            under capacity
	                                    │                     │
	                                    ▼                     │
	                         ┌────────────────────┐           │
	                         │ Evict oldest:      │           │
	                         │  - Back() from list│           │
	                         │  - Remove element  │           │
	                         │  - Delete from map │           │
	                         └────────────────────┘           │
	                                    │                     │
	                                    └──────────┬──────────┘
	                                               │
	                                               ▼
	                                    ┌────────────────────┐
	                                    │ PushFront new entry│
	                                    │ Store elem in map  │
	                                    └────────────────────┘

# Why O(1)?

The naive LRU approach iterates the map to find the oldest entry: O(n).
This implementation achieves O(1) by:

 1. The doubly-linked list maintains insertion/access order
 2. list.Back() returns the LRU element in O(1)
 3. list.Remove() is O(1) given a pointer to the element
 4. The map stores element pointers, enabling direct list manipulation

# Thread Safety

The cache uses separate mutexes for citizens and sanctions to reduce lock
contention. Each operation acquires only the lock it needs.

# TTL and Eviction Strategy

  - TTL Expiration: Entries expire after cacheTTL duration
  - Lazy Cleanup: Expired entries are removed on access (no background scan needed)
  - LRU Eviction: When at capacity, the least recently accessed entry is evicted
  - Periodic Cleanup: CleanupExpired() can be called by a background goroutine

# Regulated Mode

Citizen records track whether they were stored in regulated (PII-minimized) mode.
Cache lookups require matching regulated state to prevent serving stale PII when
the system switches modes.
*/
package store

import (
	"container/list"
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
	key       string // Cache key for LRU list reference
	record    models.CitizenRecord
	storedAt  time.Time
	regulated bool // Track whether this record was stored in minimized (regulated) mode
}

type cachedSanction struct {
	key      string // Cache key for LRU list reference
	record   models.SanctionsRecord
	storedAt time.Time
}

// InMemoryCache provides an in-memory cache for registry records with TTL expiration
// and LRU eviction. Citizen records track their regulated mode to prevent serving
// stale PII when the system switches between regulated and non-regulated modes.
//
// The cache has separate locks for citizens and sanctions to reduce contention.
// Expired entries are cleaned up lazily on access and periodically via background cleanup.
type InMemoryCache struct {
	citizenMu   sync.Mutex
	sanctionMu  sync.Mutex
	citizens    map[string]*list.Element // key -> LRU list element containing *cachedCitizen
	sanctions   map[string]*list.Element // key -> LRU list element containing *cachedSanction
	citizenLRU  *list.List               // Front = most recent, Back = least recent
	sanctionLRU *list.List
	cacheTTL    time.Duration
	maxSize     int
	metrics     *metrics.Metrics
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
		citizens:    make(map[string]*list.Element),
		sanctions:   make(map[string]*list.Element),
		citizenLRU:  list.New(),
		sanctionLRU: list.New(),
		cacheTTL:    cacheTTL,
		maxSize:     DefaultMaxCacheSize,
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

	keyStr := key.String()
	c.citizenMu.Lock()
	defer c.citizenMu.Unlock()

	// If key already exists, update and move to front
	if elem, ok := c.citizens[keyStr]; ok {
		cached := elem.Value.(*cachedCitizen) //nolint:errcheck // type-safe: citizenLRU only stores *cachedCitizen
		cached.record = *record
		cached.storedAt = time.Now()
		cached.regulated = regulated
		c.citizenLRU.MoveToFront(elem)
		return nil
	}

	// Evict oldest entry if at capacity (O(1) - remove from back of list)
	if c.citizenLRU.Len() >= c.maxSize {
		c.evictOldestCitizenLocked()
	}

	// Add new entry at front of LRU list
	cached := &cachedCitizen{
		key:       keyStr,
		record:    *record,
		storedAt:  time.Now(),
		regulated: regulated,
	}
	elem := c.citizenLRU.PushFront(cached)
	c.citizens[keyStr] = elem
	return nil
}

// FindCitizen retrieves a cached citizen record by national ID.
// Returns ErrNotFound if:
//   - The record does not exist
//   - The record has expired past the cache TTL
//   - The stored regulated mode doesn't match the requested mode (prevents stale PII)
func (c *InMemoryCache) FindCitizen(_ context.Context, nationalID id.NationalID, regulated bool) (*models.CitizenRecord, error) {
	start := time.Now()
	keyStr := nationalID.String()

	c.citizenMu.Lock()
	defer c.citizenMu.Unlock()

	elem, ok := c.citizens[keyStr]
	if !ok {
		c.recordMiss("citizen", start)
		return nil, ErrNotFound
	}

	cached := elem.Value.(*cachedCitizen) //nolint:errcheck // type-safe: citizenLRU only stores *cachedCitizen

	// Check TTL expiration
	if time.Since(cached.storedAt) >= c.cacheTTL {
		// Lazy cleanup: remove expired entry
		c.citizenLRU.Remove(elem)
		delete(c.citizens, keyStr)
		c.recordMiss("citizen", start)
		return nil, ErrNotFound
	}

	// Cache miss if regulated mode changed - prevents serving stale PII
	if cached.regulated != regulated {
		c.recordMiss("citizen", start)
		return nil, ErrNotFound
	}

	// Move to front of LRU list (O(1) access update)
	c.citizenLRU.MoveToFront(elem)

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

	keyStr := key.String()
	c.sanctionMu.Lock()
	defer c.sanctionMu.Unlock()

	// If key already exists, update and move to front
	if elem, ok := c.sanctions[keyStr]; ok {
		cached := elem.Value.(*cachedSanction) //nolint:errcheck // type-safe: sanctionLRU only stores *cachedSanction
		cached.record = *record
		cached.storedAt = time.Now()
		c.sanctionLRU.MoveToFront(elem)
		return nil
	}

	// Evict oldest entry if at capacity (O(1) - remove from back of list)
	if c.sanctionLRU.Len() >= c.maxSize {
		c.evictOldestSanctionLocked()
	}

	// Add new entry at front of LRU list
	cached := &cachedSanction{
		key:      keyStr,
		record:   *record,
		storedAt: time.Now(),
	}
	elem := c.sanctionLRU.PushFront(cached)
	c.sanctions[keyStr] = elem
	return nil
}

// FindSanction retrieves a cached sanctions record by national ID.
// Returns ErrNotFound if the record does not exist or has expired past the cache TTL.
func (c *InMemoryCache) FindSanction(_ context.Context, nationalID id.NationalID) (*models.SanctionsRecord, error) {
	start := time.Now()
	keyStr := nationalID.String()

	c.sanctionMu.Lock()
	defer c.sanctionMu.Unlock()

	elem, ok := c.sanctions[keyStr]
	if !ok {
		c.recordMiss("sanctions", start)
		return nil, ErrNotFound
	}

	cached := elem.Value.(*cachedSanction) //nolint:errcheck // type-safe: sanctionLRU only stores *cachedSanction

	// Check TTL expiration
	if time.Since(cached.storedAt) >= c.cacheTTL {
		// Lazy cleanup: remove expired entry
		c.sanctionLRU.Remove(elem)
		delete(c.sanctions, keyStr)
		c.recordMiss("sanctions", start)
		return nil, ErrNotFound
	}

	// Move to front of LRU list (O(1) access update)
	c.sanctionLRU.MoveToFront(elem)

	c.recordHit("sanctions", start)
	return &cached.record, nil
}

// evictOldestCitizenLocked removes the least recently accessed citizen entry.
// O(1) operation - removes from back of LRU list.
// Must be called with citizenMu held.
func (c *InMemoryCache) evictOldestCitizenLocked() {
	elem := c.citizenLRU.Back()
	if elem == nil {
		return
	}
	cached := elem.Value.(*cachedCitizen) //nolint:errcheck // type-safe: citizenLRU only stores *cachedCitizen
	c.citizenLRU.Remove(elem)
	delete(c.citizens, cached.key)
}

// evictOldestSanctionLocked removes the least recently accessed sanction entry.
// O(1) operation - removes from back of LRU list.
// Must be called with sanctionMu held.
func (c *InMemoryCache) evictOldestSanctionLocked() {
	elem := c.sanctionLRU.Back()
	if elem == nil {
		return
	}
	cached := elem.Value.(*cachedSanction) //nolint:errcheck // type-safe: sanctionLRU only stores *cachedSanction
	c.sanctionLRU.Remove(elem)
	delete(c.sanctions, cached.key)
}

// Size returns the current number of entries in each cache.
func (c *InMemoryCache) Size() (citizens, sanctions int) {
	c.citizenMu.Lock()
	citizens = c.citizenLRU.Len()
	c.citizenMu.Unlock()

	c.sanctionMu.Lock()
	sanctions = c.sanctionLRU.Len()
	c.sanctionMu.Unlock()

	return citizens, sanctions
}

// ClearAll removes all entries from both caches.
// This is used for cache invalidation, such as when regulated mode changes.
func (c *InMemoryCache) ClearAll() {
	c.citizenMu.Lock()
	c.citizens = make(map[string]*list.Element)
	c.citizenLRU.Init()
	c.citizenMu.Unlock()

	c.sanctionMu.Lock()
	c.sanctions = make(map[string]*list.Element)
	c.sanctionLRU.Init()
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
