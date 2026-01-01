package store

import (
	"context"
	"sync"

	"credo/internal/evidence/vc/models"
	id "credo/pkg/domain"
)

// InMemoryStore is an in-memory implementation of Store for tests or local use.
// It is safe for concurrent access but does not persist across process restarts.
type InMemoryStore struct {
	mu          sync.RWMutex
	credentials map[string]models.CredentialRecord
}

// NewInMemoryStore constructs an empty in-memory credential store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{credentials: make(map[string]models.CredentialRecord)}
}

// Save stores or overwrites a credential record by ID.
func (s *InMemoryStore) Save(_ context.Context, credential models.CredentialRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credentials[credential.ID.String()] = credential
	return nil
}

// FindByID retrieves a credential record by ID or returns ErrNotFound.
func (s *InMemoryStore) FindByID(_ context.Context, id models.CredentialID) (models.CredentialRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if vc, ok := s.credentials[id.String()]; ok {
		return vc, nil
	}
	return models.CredentialRecord{}, ErrNotFound
}

// FindBySubjectAndType returns the most recently issued credential for a subject and type.
func (s *InMemoryStore) FindBySubjectAndType(_ context.Context, subject id.UserID, credType models.CredentialType) (models.CredentialRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var found *models.CredentialRecord
	for _, cred := range s.credentials {
		if cred.Subject == subject && cred.Type == credType {
			c := cred // avoid loop variable capture
			if found == nil || c.IssuedAt.After(found.IssuedAt) {
				found = &c
			}
		}
	}
	if found == nil {
		return models.CredentialRecord{}, ErrNotFound
	}
	return *found, nil
}
