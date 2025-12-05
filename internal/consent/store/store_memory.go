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

func (s *InMemoryStore) ListByUser(_ context.Context, userID string) ([]*models.ConsentRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]*models.ConsentRecord{}, s.consents[userID]...), nil
}

func (s *InMemoryStore) Revoke(_ context.Context, userID string, purpose models.ConsentPurpose, revokedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	records := s.consents[userID]
	for i := range records {
		if records[i].Purpose == purpose {
			records[i].RevokedAt = &revokedAt
		}
	}
	s.consents[userID] = records
	return nil
}
