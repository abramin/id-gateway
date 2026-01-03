package adapters

import (
	"sync"
	"time"

	"credo/internal/auth/types"
)

// clientCacheEntry holds cached client and tenant data with expiration.
type clientCacheEntry struct {
	client    *types.ResolvedClient
	tenant    *types.ResolvedTenant
	expiresAt time.Time
}

// clientCache provides a simple in-memory cache for client resolution.
// Thread-safe with TTL-based expiration.
type clientCache struct {
	mu      sync.RWMutex
	entries map[string]*clientCacheEntry
	ttl     time.Duration
}

// newClientCache creates a new client cache with the given TTL.
func newClientCache(ttl time.Duration) *clientCache {
	return &clientCache{
		entries: make(map[string]*clientCacheEntry),
		ttl:     ttl,
	}
}

// Get retrieves a cached entry if it exists and hasn't expired.
func (c *clientCache) Get(clientID string) (*types.ResolvedClient, *types.ResolvedTenant, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[clientID]
	if !ok {
		return nil, nil, false
	}

	if time.Now().After(entry.expiresAt) {
		// Expired - treat as miss (cleanup happens lazily on Set)
		return nil, nil, false
	}

	return entry.client, entry.tenant, true
}

// Set stores a client and tenant in the cache.
func (c *clientCache) Set(clientID string, client *types.ResolvedClient, tenant *types.ResolvedTenant) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[clientID] = &clientCacheEntry{
		client:    client,
		tenant:    tenant,
		expiresAt: time.Now().Add(c.ttl),
	}

	// Lazy cleanup: remove expired entries (limit to avoid holding lock too long)
	c.cleanupExpiredLocked(10)
}

// cleanupExpiredLocked removes up to maxCleanup expired entries.
// Must be called with lock held.
func (c *clientCache) cleanupExpiredLocked(maxCleanup int) {
	now := time.Now()
	cleaned := 0
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
			cleaned++
			if cleaned >= maxCleanup {
				break
			}
		}
	}
}
