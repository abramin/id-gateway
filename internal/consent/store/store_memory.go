package store

import (
	"context"
	"sync"
	"time"

	"credo/internal/consent/models"
	dErrors "credo/pkg/domain-errors"
)

// ErrNotFound is returned when a requested record is not found in the store.
// Services should check for this error using errors.Is(err, store.ErrNotFound).
var ErrNotFound = dErrors.New(dErrors.CodeNotFound, "record not found")

// Error Contract:
// All store methods follow this error pattern:
// - Return ErrNotFound when the requested entity does not exist
// - Return nil for successful operations
// - Return wrapped errors with context for infrastructure failures (future: DB errors, network issues, etc.)

type InMemoryStore struct {
	mu       sync.RWMutex
	consents map[string][]*models.Record
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{consents: make(map[string][]*models.Record)}
}

func (s *InMemoryStore) Save(_ context.Context, consent *models.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.consents[consent.UserID] = append(s.consents[consent.UserID], consent)
	return nil
}

func (s *InMemoryStore) FindByUserAndPurpose(_ context.Context, userID string, purpose models.Purpose) (*models.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	records := s.consents[userID]
	for i := len(records) - 1; i >= 0; i-- {
		if records[i].Purpose == purpose {
			copyRecord := *records[i]
			return &copyRecord, nil
		}
	}
	return nil, ErrNotFound
}

func (s *InMemoryStore) ListByUser(_ context.Context, userID string, filter *models.RecordFilter) ([]*models.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	records := s.consents[userID]

	var filtered []*models.Record
	now := time.Now()

	for _, record := range records {
		// Apply filters if specified
		if filter != nil {
			if filter.Purpose != "" && string(record.Purpose) != filter.Purpose {
				continue
			}
			if filter.Status != "" {
				status := record.ComputeStatus(now)
				if string(status) != filter.Status {
					continue
				}
			}
		}

		// Return a copy to prevent external modifications
		copyRecord := *record
		filtered = append(filtered, &copyRecord)
	}

	return filtered, nil
}

func (s *InMemoryStore) Update(_ context.Context, consent *models.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	records := s.consents[consent.UserID]
	for i := range records {
		if records[i].ID == consent.ID {
			records[i] = consent
			s.consents[consent.UserID] = records
			return nil
		}
	}
	return nil
}

func (s *InMemoryStore) RevokeByUserAndPurpose(_ context.Context, userID string, purpose models.Purpose, revokedAt time.Time) (*models.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	records := s.consents[userID]
	result := &models.Record{}
	for i := range records {
		if records[i].Purpose == purpose && records[i].RevokedAt == nil {
			records[i].RevokedAt = &revokedAt
			result = records[i]
			break
		}
	}
	s.consents[userID] = records
	return result, nil
}

func (s *InMemoryStore) DeleteByUser(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.consents, userID)
	return nil
}
