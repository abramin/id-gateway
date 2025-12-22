package authlockout

import (
	"context"
	"sync"
	"time"

	"credo/internal/ratelimit/models"
	requesttime "credo/pkg/platform/middleware/requesttime"
)

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

func (s *InMemoryAuthLockoutStore) RecordFailure(ctx context.Context, identifier string) (*models.AuthLockout, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := requesttime.Now(ctx)
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

func (s *InMemoryAuthLockoutStore) Clear(_ context.Context, identifier string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.records, identifier)
	return nil
}

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
