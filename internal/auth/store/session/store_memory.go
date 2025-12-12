package session

import (
	"context"
	"sync"

	"github.com/google/uuid"

	"credo/internal/auth/models"
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
//
// In-memory stores keep the initial implementation lightweight and testable.
// They intentionally favor clarity over performance.
type InMemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*models.Session
}

func NewInMemorySessionStore() *InMemorySessionStore {
	return &InMemorySessionStore{sessions: make(map[string]*models.Session)}
}

func (s *InMemorySessionStore) Save(_ context.Context, session *models.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID.String()] = session
	return nil
}

func (s *InMemorySessionStore) FindByID(_ context.Context, id uuid.UUID) (*models.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if session, ok := s.sessions[id.String()]; ok {
		return session, nil
	}
	return nil, ErrNotFound
}

func (s *InMemorySessionStore) FindByCode(_ context.Context, code string) (*models.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, session := range s.sessions {
		if session.Code == code {
			return session, nil
		}
	}
	return nil, ErrNotFound
}

func (s *InMemorySessionStore) DeleteSessionsByUser(_ context.Context, userID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	found := false
	for id, session := range s.sessions {
		if session.UserID == userID {
			delete(s.sessions, id)
			found = true
		}
	}

	if !found {
		return ErrNotFound
	}

	return nil
}
