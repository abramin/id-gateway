package authlockout

import (
	"context"
	"sync"
	"time"

	"credo/internal/ratelimit/models"
)

// InMemoryAuthLockoutStore implements AuthLockoutStore using in-memory storage.
type InMemoryAuthLockoutStore struct {
	mu      sync.RWMutex
	records map[string]*models.AuthLockout // keyed by identifier
}

// New creates a new in-memory auth lockout store.
func New() *InMemoryAuthLockoutStore {
	return &InMemoryAuthLockoutStore{
		records: make(map[string]*models.AuthLockout),
	}
}

// Get retrieves the current lockout state for an identifier.
func (s *InMemoryAuthLockoutStore) Get(_ context.Context, identifier string) (*models.AuthLockout, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if record, exists := s.records[identifier]; exists {
		return record, nil
	}
	return nil, nil
}

// RecordFailure records a failed authentication attempt and returns the updated state.
func (s *InMemoryAuthLockoutStore) RecordFailure(_ context.Context, identifier string) (*models.AuthLockout, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if existing, exists := s.records[identifier]; exists {
		existing.FailureCount++
		existing.DailyFailures++
		existing.LastFailureAt = now
		return existing, nil
	}

	record := &models.AuthLockout{
		Identifier:      identifier,
		FailureCount:    1,
		DailyFailures:   1,
		LastFailureAt:   now,
		LockedUntil:     nil,
		RequiresCaptcha: false,
	}
	s.records[identifier] = record
	return record, nil
}

// Clear clears the lockout state after successful authentication.
func (s *InMemoryAuthLockoutStore) Clear(_ context.Context, identifier string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.records, identifier)
	return nil
}

// IsLocked checks if an identifier is currently locked out.
func (s *InMemoryAuthLockoutStore) IsLocked(_ context.Context, identifier string) (bool, *time.Time, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if record, exists := s.records[identifier]; exists {
		if record.IsLocked() {
			return true, record.LockedUntil, nil
		}
	}
	return false, nil, nil
}

func (s *InMemoryAuthLockoutStore) Update(_ context.Context, record *models.AuthLockout) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.records[record.Identifier] = record
	return nil
}
