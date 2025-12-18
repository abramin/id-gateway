package allowlist

import (
	"context"
	"sync"
	"time"

	"credo/internal/ratelimit/models"
)

type InMemoryAllowlistStore struct {
	mu      sync.RWMutex
	entries map[string]*models.AllowlistEntry // keyed by "{type}:{identifier}"
}

func NewInMemoryAllowlistStore() *InMemoryAllowlistStore {
	return &InMemoryAllowlistStore{
		entries: make(map[string]*models.AllowlistEntry),
	}
}

// TODO: Add to Redis set with optional TTL.
func (s *InMemoryAllowlistStore) Add(ctx context.Context, entry *models.AllowlistEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := buildKey(entry.Type, entry.Identifier)
	s.entries[key] = entry
	return nil
}

func (s *InMemoryAllowlistStore) Remove(ctx context.Context, entryType models.AllowlistEntryType, identifier string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := buildKey(entryType, identifier)
	delete(s.entries, key)
	return nil
}

func (s *InMemoryAllowlistStore) IsAllowlisted(ctx context.Context, identifier string) (bool, error) {
	if identifier == "" {
		return false, nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	typesToCheck := []models.AllowlistEntryType{models.AllowlistTypeIP, models.AllowlistTypeUserID}
	for _, entryType := range typesToCheck {
		key := buildKey(entryType, identifier)
		if entry, exists := s.entries[key]; exists {
			if !isExpired(entry) {
				return true, nil
			}
			delete(s.entries, key)
		}
	}
	return false, nil // Default to not allowlisted
}

// List returns all active (non-expired) allowlist entries.
func (s *InMemoryAllowlistStore) List(ctx context.Context) ([]*models.AllowlistEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	activeEntries := make([]*models.AllowlistEntry, 0)
	for _, entry := range s.entries {
		if !isExpired(entry) {
			activeEntries = append(activeEntries, entry)
		}
	}
	return activeEntries, nil
}

func buildKey(entryType models.AllowlistEntryType, identifier string) string {
	return string(entryType) + ":" + identifier
}

func isExpired(entry *models.AllowlistEntry) bool {
	if entry.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*entry.ExpiresAt)
}
