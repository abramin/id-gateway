package allowlist

import (
	"context"
	"sync"
	"time"

	"credo/internal/ratelimit/models"
	dErrors "credo/pkg/domain-errors"
)

// InMemoryAllowlistStore implements AllowlistStore using in-memory storage.
// Per PRD-017 FR-4: Allowlist bypass for rate limits.
type InMemoryAllowlistStore struct {
	mu      sync.RWMutex
	entries map[string]*models.AllowlistEntry // keyed by "{type}:{identifier}"
}

// NewInMemoryAllowlistStore creates a new in-memory allowlist store.
func NewInMemoryAllowlistStore() *InMemoryAllowlistStore {
	return &InMemoryAllowlistStore{
		entries: make(map[string]*models.AllowlistEntry),
	}
}

// Add adds an identifier to the allowlist.
// Per PRD-017 FR-4: Add to Redis set with optional TTL.
//
// TODO: Implement this method
// 1. Build key: "{type}:{identifier}"
// 2. Check if entry already exists
// 3. Store entry
func (s *InMemoryAllowlistStore) Add(ctx context.Context, entry *models.AllowlistEntry) error {
	// TODO: Implement
	return dErrors.New(dErrors.CodeInternal, "not implemented")
}

// Remove removes an identifier from the allowlist.
// Per PRD-017 FR-4: Remove from allowlist.
//
// TODO: Implement this method
func (s *InMemoryAllowlistStore) Remove(ctx context.Context, entryType models.AllowlistEntryType, identifier string) error {
	// TODO: Implement
	return dErrors.New(dErrors.CodeInternal, "not implemented")
}

// IsAllowlisted checks if an identifier is in the allowlist and not expired.
// Per PRD-017 TR-1, FR-4: Check allowlist before rate limiting.
//
// TODO: Implement this method
// 1. Check both "ip:{identifier}" and "user_id:{identifier}" keys
// 2. If found, check expiration
// 3. If expired, optionally clean up
// 4. Return true if found and not expired
func (s *InMemoryAllowlistStore) IsAllowlisted(ctx context.Context, identifier string) (bool, error) {
	// TODO: Implement
	return false, nil // Default to not allowlisted
}

// List returns all active (non-expired) allowlist entries.
//
// TODO: Implement this method
// 1. Iterate all entries
// 2. Filter out expired entries
// 3. Return list
func (s *InMemoryAllowlistStore) List(ctx context.Context) ([]*models.AllowlistEntry, error) {
	// TODO: Implement
	return nil, dErrors.New(dErrors.CodeInternal, "not implemented")
}

// buildKey creates the map key for an allowlist entry.
func buildKey(entryType models.AllowlistEntryType, identifier string) string {
	return string(entryType) + ":" + identifier
}

// isExpired checks if an entry has expired.
func isExpired(entry *models.AllowlistEntry) bool {
	if entry.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*entry.ExpiresAt)
}
