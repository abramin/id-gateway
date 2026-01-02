package authlockout

import (
	"context"
	"sync"
	"time"

	"credo/internal/ratelimit/models"
)

// InMemoryAuthLockoutStore is for testing only. Use PostgresStore in production.
// This store is pure I/O—all domain logic belongs in the service.
type InMemoryAuthLockoutStore struct {
	mu      sync.RWMutex
	records map[string]*models.AuthLockout // keyed by identifier
}

func New() *InMemoryAuthLockoutStore {
	return &InMemoryAuthLockoutStore{
		records: make(map[string]*models.AuthLockout),
	}
}

func (s *InMemoryAuthLockoutStore) Get(_ context.Context, identifier string) (*models.AuthLockout, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if record, exists := s.records[identifier]; exists {
		return record, nil
	}
	return nil, nil
}

// GetOrCreate retrieves an existing lockout record or creates a new one with zero counts.
// This is pure I/O—the service owns counter increments via domain methods.
func (s *InMemoryAuthLockoutStore) GetOrCreate(_ context.Context, identifier string, now time.Time) (*models.AuthLockout, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, exists := s.records[identifier]; exists {
		return existing, nil
	}

	record := &models.AuthLockout{
		Identifier:      identifier,
		FailureCount:    0,
		DailyFailures:   0,
		LastFailureAt:   now,
		LockedUntil:     nil,
		RequiresCaptcha: false,
	}
	s.records[identifier] = record
	return record, nil
}

func (s *InMemoryAuthLockoutStore) Clear(_ context.Context, identifier string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.records, identifier)
	return nil
}

func (s *InMemoryAuthLockoutStore) Update(_ context.Context, record *models.AuthLockout) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.records[record.Identifier] = record
	return nil
}

// ResetFailureCount resets window failure counts for records with last_failure_at before cutoff.
func (s *InMemoryAuthLockoutStore) ResetFailureCount(_ context.Context, cutoff time.Time) (failuresReset int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, record := range s.records {
		if record.LastFailureAt.Before(cutoff) {
			failuresReset += record.FailureCount
			record.FailureCount = 0
		}
	}
	return failuresReset, nil
}

// ResetDailyFailures resets daily failure counts for records with last_failure_at before cutoff.
func (s *InMemoryAuthLockoutStore) ResetDailyFailures(_ context.Context, cutoff time.Time) (failuresReset int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, record := range s.records {
		if record.LastFailureAt.Before(cutoff) {
			failuresReset += record.DailyFailures
			record.DailyFailures = 0
		}
	}
	return failuresReset, nil
}
