package store

import (
	"context"
	"sync"
	"time"

	"credo/internal/consent/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"
	"credo/pkg/requestcontext"
)

// Error Contract:
// All store methods follow this error pattern:
// - Return ErrNotFound when the requested entity does not exist
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
	s.mu.Lock()
	defer s.mu.Unlock()
	records, ok := s.consents[consent.UserID]
	if !ok {
		records = make(map[models.Purpose]*models.Record)
		s.consents[consent.UserID] = records
	}
	if existing, ok := records[consent.Purpose]; ok {
		consent.ID = existing.ID
	}
	copyRecord := *consent
	records[consent.Purpose] = &copyRecord
	return nil
}

func (s *InMemoryStore) FindByUserAndPurpose(_ context.Context, userID id.UserID, purpose models.Purpose) (*models.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	records := s.consents[userID]
	record, ok := records[purpose]
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
	now := requestcontext.Now(ctx)

	for _, record := range records {
		// Apply filters if specified
		if filter != nil {
			if filter.Purpose != nil && record.Purpose != *filter.Purpose {
				continue
			}
			if filter.Status != nil {
				status := record.ComputeStatus(now)
				if status != *filter.Status {
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

// RevokeByUserAndPurpose sets the RevokedAt timestamp for the latest active consent of the given purpose.
// Returns the updated consent record or ErrNotFound if no active consent exists.
func (s *InMemoryStore) RevokeByUserAndPurpose(_ context.Context, userID id.UserID, purpose models.Purpose, revokedAt time.Time) (*models.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	records := s.consents[userID]
	record, ok := records[purpose]
	if !ok || record.RevokedAt != nil {
		return nil, sentinel.ErrNotFound
	}
	record.RevokedAt = &revokedAt
	s.consents[userID] = records
	copyRecord := *record
	return &copyRecord, nil
}

func (s *InMemoryStore) DeleteByUser(_ context.Context, userID id.UserID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.consents, userID)
	return nil
}

// RevokeAllByUser revokes all active consents for a user.
// Returns the count of consents that were revoked.
func (s *InMemoryStore) RevokeAllByUser(_ context.Context, userID id.UserID, revokedAt time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	records := s.consents[userID]
	count := 0
	for _, record := range records {
		if record.RevokedAt == nil {
			record.RevokedAt = &revokedAt
			count++
		}
	}
	s.consents[userID] = records
	return count, nil
}
