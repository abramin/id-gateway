package idempotency

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// CachedResponse represents a cached response for idempotency.
type CachedResponse struct {
	StatusCode int             `json:"status_code"`
	Body       json.RawMessage `json:"body"`
	ExpiresAt  time.Time       `json:"expires_at"`
}

// Store provides idempotency key storage for preventing duplicate request processing.
type Store interface {
	// Get retrieves a cached response for the given idempotency key.
	// Returns nil if not found or expired.
	Get(ctx context.Context, key string) (*CachedResponse, error)

	// Set stores a response for the given idempotency key with TTL.
	Set(ctx context.Context, key string, response *CachedResponse) error
}

// InMemory provides an in-memory idempotency store with automatic cleanup.
type InMemory struct {
	mu      sync.RWMutex
	entries map[string]*CachedResponse
	ttl     time.Duration
}

// NewInMemory creates an in-memory idempotency store with the given TTL.
func NewInMemory(ttl time.Duration) *InMemory {
	store := &InMemory{
		entries: make(map[string]*CachedResponse),
		ttl:     ttl,
	}
	// Start background cleanup goroutine
	go store.cleanupLoop()
	return store
}

// Get retrieves a cached response for the given idempotency key.
func (s *InMemory) Get(_ context.Context, key string) (*CachedResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.entries[key]
	if !ok {
		return nil, nil
	}
	if time.Now().After(entry.ExpiresAt) {
		return nil, nil
	}
	return entry, nil
}

// Set stores a response for the given idempotency key.
func (s *InMemory) Set(_ context.Context, key string, response *CachedResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	response.ExpiresAt = time.Now().Add(s.ttl)
	s.entries[key] = response
	return nil
}

// cleanupLoop periodically removes expired entries.
func (s *InMemory) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.cleanup()
	}
}

func (s *InMemory) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for key, entry := range s.entries {
		if now.After(entry.ExpiresAt) {
			delete(s.entries, key)
		}
	}
}
