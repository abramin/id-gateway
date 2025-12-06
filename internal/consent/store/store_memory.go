package store

import (
	"context"
	"sync"
	"time"

	"id-gateway/internal/consent/models"
)

type InMemoryStore struct {
	mu       sync.RWMutex
	consents map[string][]*models.ConsentRecord
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{consents: make(map[string][]*models.ConsentRecord)}
}

func (s *InMemoryStore) Save(_ context.Context, consent *models.ConsentRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.consents[consent.UserID] = append(s.consents[consent.UserID], consent)
	return nil
}

func (s *InMemoryStore) FindByUserAndPurpose(_ context.Context, userID string, purpose models.ConsentPurpose) (*models.ConsentRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	records := s.consents[userID]
	for i := len(records) - 1; i >= 0; i-- {
		if records[i].Purpose == purpose {
			copyRecord := *records[i]
			return &copyRecord, nil
		}
	}
	return nil, nil
}

func (s *InMemoryStore) ListByUser(_ context.Context, userID string) ([]*models.ConsentRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	records := s.consents[userID]
	copies := make([]*models.ConsentRecord, len(records))
	for i, record := range records {
		copyRecord := *record
		copies[i] = &copyRecord
	}
	return copies, nil
}

func (s *InMemoryStore) Update(_ context.Context, consent *models.ConsentRecord) error {
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

func (s *InMemoryStore) RevokeByUserAndPurpose(_ context.Context, userID string, purpose models.ConsentPurpose, revokedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	records := s.consents[userID]
	for i := range records {
		if records[i].Purpose == purpose && records[i].RevokedAt == nil {
			records[i].RevokedAt = &revokedAt
		}
	}
	s.consents[userID] = records
	return nil
}

func (s *InMemoryStore) DeleteByUser(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.consents, userID)
	return nil
}
