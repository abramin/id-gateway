package session

import (
	"context"
	"fmt"
	"maps"
	"sync"
	"time"

	"credo/internal/auth/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"
)

var ErrSessionRevoked = fmt.Errorf("session has been revoked: %w", sentinel.ErrInvalidState)

// Error Contract:
// All store methods follow this error pattern:
// - Return ErrNotFound when the requested entity does not exist
// - Return nil for successful operations
// - Return wrapped errors with context for infrastructure failures (future: DB errors, network issues, etc.)
// InMemorySessionStore stores sessions in memory for tests/dev.
type InMemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[id.SessionID]*models.Session
}

// New constructs an empty in-memory session store.
func New() *InMemorySessionStore {
	return &InMemorySessionStore{sessions: make(map[id.SessionID]*models.Session)}
}

func (s *InMemorySessionStore) Create(_ context.Context, session *models.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
	return nil
}

func (s *InMemorySessionStore) FindByID(_ context.Context, sessionID id.SessionID) (*models.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if session, ok := s.sessions[sessionID]; ok {
		return session, nil
	}
	return nil, fmt.Errorf("session not found: %w", sentinel.ErrNotFound)
}

func (s *InMemorySessionStore) ListByUser(_ context.Context, userID id.UserID) ([]*models.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sessions := make([]*models.Session, 0)
	for _, session := range s.sessions {
		if session.UserID == userID {
			sessions = append(sessions, session)
		}
	}

	return sessions, nil
}

func (s *InMemorySessionStore) UpdateSession(_ context.Context, session *models.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[session.ID]; !ok {
		return fmt.Errorf("session not found: %w", sentinel.ErrNotFound)
	}
	s.sessions[session.ID] = session
	return nil
}

func (s *InMemorySessionStore) DeleteSessionsByUser(_ context.Context, userID id.UserID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	found := false
	for key, session := range s.sessions {
		if session.UserID == userID {
			delete(s.sessions, key)
			found = true
		}
	}

	if !found {
		return fmt.Errorf("session not found: %w", sentinel.ErrNotFound)
	}

	return nil
}

func (s *InMemorySessionStore) RevokeSession(ctx context.Context, sessionID id.SessionID) error {
	return s.RevokeSessionIfActive(ctx, sessionID, time.Now())
}

func (s *InMemorySessionStore) RevokeSessionIfActive(_ context.Context, sessionID id.SessionID, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return sentinel.ErrNotFound
	}

	if !session.Revoke(now) {
		return ErrSessionRevoked
	}

	s.sessions[sessionID] = session
	return nil
}

// DeleteExpiredSessions removes all sessions that have expired as of the given time.
// The time parameter is injected for testability (no hidden time.Now() calls).
func (s *InMemorySessionStore) DeleteExpiredSessions(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	deletedCount := 0
	for id, session := range s.sessions {
		if session.ExpiresAt.Before(now) {
			delete(s.sessions, id)
			deletedCount++
		}
	}

	return deletedCount, nil
}

func (s *InMemorySessionStore) ListAll(_ context.Context) (map[id.SessionID]*models.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[id.SessionID]*models.Session, len(s.sessions))
	maps.Copy(result, s.sessions)
	return result, nil
}

// Execute atomically validates and mutates a session under lock.
// The validate callback runs first; if it returns an error (typically a domain error),
// that error is returned as-is without translation.
// The mutate callback applies changes to the session after validation passes.
// Returns sentinel.ErrNotFound if the session doesn't exist.
func (s *InMemorySessionStore) Execute(_ context.Context, sessionID id.SessionID, validate func(*models.Session) error, mutate func(*models.Session)) (*models.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return nil, sentinel.ErrNotFound
	}

	if err := validate(session); err != nil {
		return nil, err // Domain error from callback - passed through unchanged
	}

	mutate(session)
	s.sessions[sessionID] = session
	return session, nil
}
