package store

import (
	"context"
	"errors"
	"sync"
	"time"

	"credo/internal/evidence/registry/models"
	id "credo/pkg/domain"
)

type cachedCitizen struct {
	record    models.CitizenRecord
	storedAt  time.Time
	regulated bool // Track whether this record was stored in minimized (regulated) mode
}

type cachedSanction struct {
	record   models.SanctionsRecord
	storedAt time.Time
}

// InMemoryCache provides an in-memory cache for registry records with TTL expiration.
// Citizen records track their regulated mode to prevent serving stale PII when
// the system switches between regulated and non-regulated modes.
type InMemoryCache struct {
	mu        sync.RWMutex
	citizens  map[string]cachedCitizen
	sanctions map[string]cachedSanction
	cacheTTL  time.Duration
}

// ErrNotFound is returned when a requested record does not exist in the cache.
var ErrNotFound = errors.New("not found")

// NewInMemoryCache creates a new in-memory cache with the specified TTL.
func NewInMemoryCache(cacheTTL time.Duration) *InMemoryCache {
	return &InMemoryCache{
		citizens:  make(map[string]cachedCitizen),
		sanctions: make(map[string]cachedSanction),
		cacheTTL:  cacheTTL,
	}
}

// SaveCitizen stores a citizen record in the cache, keyed by national ID.
// The regulated parameter indicates whether the record is in minimized form.
// If record is nil, the operation is a no-op and returns nil.
func (c *InMemoryCache) SaveCitizen(_ context.Context, record *models.CitizenRecord, regulated bool) error {
	if record == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.citizens[record.NationalID] = cachedCitizen{
		record:    *record,
		storedAt:  time.Now(),
		regulated: regulated,
	}
	return nil
}

// FindCitizen retrieves a cached citizen record by national ID.
// Returns ErrNotFound if:
//   - The record does not exist
//   - The record has expired past the cache TTL
//   - The stored regulated mode doesn't match the requested mode (prevents stale PII)
func (c *InMemoryCache) FindCitizen(_ context.Context, nationalID id.NationalID, regulated bool) (*models.CitizenRecord, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if cached, ok := c.citizens[nationalID.String()]; ok {
		if time.Since(cached.storedAt) < c.cacheTTL {
			// Cache miss if regulated mode changed - prevents serving stale PII
			if cached.regulated != regulated {
				return nil, ErrNotFound
			}
			return &cached.record, nil
		}
	}
	return nil, ErrNotFound
}

// SaveSanction stores a sanctions record in the cache, keyed by national ID.
// If record is nil, the operation is a no-op and returns nil.
func (c *InMemoryCache) SaveSanction(_ context.Context, record *models.SanctionsRecord) error {
	if record == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sanctions[record.NationalID] = cachedSanction{record: *record, storedAt: time.Now()}
	return nil
}

// FindSanction retrieves a cached sanctions record by national ID.
// Returns ErrNotFound if the record does not exist or has expired past the cache TTL.
func (c *InMemoryCache) FindSanction(_ context.Context, nationalID id.NationalID) (*models.SanctionsRecord, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if cached, ok := c.sanctions[nationalID.String()]; ok {
		if time.Since(cached.storedAt) < c.cacheTTL {
			return &cached.record, nil
		}
	}
	return nil, ErrNotFound
}
