package store

import (
	"context"
	"sync"

	"credo/internal/evidence/vc/models"
)

type InMemoryStore struct {
	mu          sync.RWMutex
	credentials map[string]models.CredentialRecord
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{credentials: make(map[string]models.CredentialRecord)}
}

func (s *InMemoryStore) Save(_ context.Context, credential models.CredentialRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credentials[credential.ID.String()] = credential
	return nil
}

func (s *InMemoryStore) FindByID(_ context.Context, id models.CredentialID) (models.CredentialRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if vc, ok := s.credentials[id.String()]; ok {
		return vc, nil
	}
	return models.CredentialRecord{}, ErrNotFound
}
