package store

import (
	"context"
	"fmt"
	"sync"

	"credo/internal/consent/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"
)

// Error Contract:
// All store methods follow this error pattern:
// - Return ErrNotFound when the requested entity does not exist
// - Return ErrConflict when a record already exists for user+purpose
// - Return nil for successful operations
// - Return wrapped errors with context for infrastructure failures (future: DB errors, network issues, etc.)

// InMemoryStore stores consent records in memory for tests.
type InMemoryStore struct {
	mu       sync.RWMutex
	consents map[id.UserID]map[models.Purpose]*models.Record
}

// New constructs an empty in-memory consent store.
func New() *InMemoryStore {
	return &InMemoryStore{consents: make(map[id.UserID]map[models.Purpose]*models.Record)}
}

func (s *InMemoryStore) Save(_ context.Context, consent *models.Record) error {
	if consent == nil {
		return fmt.Errorf("consent record is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	records, ok := s.consents[consent.UserID]
	if !ok {
		records = make(map[models.Purpose]*models.Record)
		s.consents[consent.UserID] = records
	}
	if _, ok := records[consent.Purpose]; ok {
		return sentinel.ErrConflict
	}
	copyRecord := *consent
	records[consent.Purpose] = &copyRecord
	return nil
}

func (s *InMemoryStore) FindByScope(_ context.Context, scope models.ConsentScope) (*models.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	records := s.consents[scope.UserID]
	record, ok := records[scope.Purpose]
	if !ok {
		return nil, sentinel.ErrNotFound
	}
	copyRecord := *record
	return &copyRecord, nil
}

func (s *InMemoryStore) ListByUser(ctx context.Context, userID id.UserID, filter *models.RecordFilter) ([]*models.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	records := s.consents[userID]

	var filtered []*models.Record
	for _, record := range records {
		// Apply filters if specified
		if filter != nil {
			if filter.Purpose != nil && record.Purpose != *filter.Purpose {
				continue
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
	record, ok := records[consent.Purpose]
	if !ok {
		return sentinel.ErrNotFound
	}
	if record.ID != consent.ID {
		return sentinel.ErrNotFound
	}
	copyRecord := *consent
	records[consent.Purpose] = &copyRecord
	s.consents[consent.UserID] = records
	return nil
}

func (s *InMemoryStore) DeleteByUser(_ context.Context, userID id.UserID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.consents, userID)
	return nil
}

// Execute atomically validates and mutates a consent record under lock.
func (s *InMemoryStore) Execute(_ context.Context, scope models.ConsentScope, validate func(*models.Record) error, mutate func(*models.Record)) (*models.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	records := s.consents[scope.UserID]
	record, ok := records[scope.Purpose]
	if !ok {
		return nil, sentinel.ErrNotFound
	}

	copyRecord := *record
	if err := validate(&copyRecord); err != nil {
		return nil, err
	}

	mutate(&copyRecord)
	records[scope.Purpose] = &copyRecord
	s.consents[scope.UserID] = records
	return &copyRecord, nil
}
