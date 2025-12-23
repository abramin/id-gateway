package session

import (
	"context"
	"fmt"
	"sync"
	"time"

	"credo/internal/auth/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"
)

// ErrNotFound is returned when a requested record is not found in the store.
// Services should check for this error using errors.Is(err, store.ErrNotFound).
var ErrNotFound = sentinel.ErrNotFound
var ErrSessionRevoked = fmt.Errorf("session has been revoked: %w", sentinel.ErrInvalidState)

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
	sessions map[id.SessionID]*models.Session
}

func NewInMemorySessionStore() *InMemorySessionStore {
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
	return nil, fmt.Errorf("session not found: %w", ErrNotFound)
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
		return fmt.Errorf("session not found: %w", ErrNotFound)
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
		return fmt.Errorf("session not found: %w", ErrNotFound)
	}

	return nil
}

func (s *InMemorySessionStore) RevokeSession(_ context.Context, sessionID id.SessionID) error {
	return s.RevokeSessionIfActive(context.Background(), sessionID, time.Now())
}

func (s *InMemorySessionStore) RevokeSessionIfActive(_ context.Context, sessionID id.SessionID, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return ErrNotFound
	}
	if session.Status == models.SessionStatusRevoked {
		return ErrSessionRevoked
	}

	session.Status = models.SessionStatusRevoked
	if session.RevokedAt == nil || now.After(*session.RevokedAt) {
		session.RevokedAt = &now
	}
	s.sessions[sessionID] = session
	return nil
}

// for use in token cleanup strategy
func (s *InMemorySessionStore) DeleteExpiredSessions(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
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

	// Return a copy to avoid concurrent map iteration/write panics
	result := make(map[id.SessionID]*models.Session, len(s.sessions))
	for k, v := range s.sessions {
		result[k] = v
	}
	return result, nil
}

func (s *InMemorySessionStore) AdvanceLastSeen(_ context.Context, sessionID id.SessionID, clientID string, at time.Time, accessTokenJTI string, activate bool, deviceID string, deviceFingerprintHash string) (*models.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session not found: %w", ErrNotFound)
	}
	if session.ClientID.String() != clientID {
		return nil, fmt.Errorf("client_id mismatch: %w", sentinel.ErrInvalidState)
	}
	if session.Status == models.SessionStatusRevoked {
		return nil, ErrSessionRevoked
	}
	if session.Status != models.SessionStatusPendingConsent && session.Status != models.SessionStatusActive {
		return nil, fmt.Errorf("session in invalid state: %w", sentinel.ErrInvalidState)
	}
	if at.After(session.ExpiresAt) {
		return nil, fmt.Errorf("session expired: %w", sentinel.ErrExpired)
	}

	if at.After(session.LastSeenAt) {
		session.LastSeenAt = at
	}
	if activate && session.Status == models.SessionStatusPendingConsent {
		session.Status = models.SessionStatusActive
	}
	if accessTokenJTI != "" {
		session.LastAccessTokenJTI = accessTokenJTI
	}
	if deviceID != "" {
		session.DeviceID = deviceID
	}
	if deviceFingerprintHash != "" {
		session.DeviceFingerprintHash = deviceFingerprintHash
	}

	s.sessions[sessionID] = session
	return session, nil
}

func (s *InMemorySessionStore) AdvanceLastRefreshed(_ context.Context, sessionID id.SessionID, clientID string, at time.Time, accessTokenJTI string, deviceID string, deviceFingerprintHash string) (*models.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session not found: %w", ErrNotFound)
	}
	if session.ClientID.String() != clientID {
		return nil, fmt.Errorf("client_id mismatch: %w", sentinel.ErrInvalidState)
	}
	if session.Status == models.SessionStatusRevoked {
		return nil, ErrSessionRevoked
	}
	if session.Status != models.SessionStatusActive {
		return nil, fmt.Errorf("session in invalid state: %w", sentinel.ErrInvalidState)
	}
	if at.After(session.ExpiresAt) {
		return nil, fmt.Errorf("session expired: %w", sentinel.ErrExpired)
	}

	if session.LastRefreshedAt == nil || at.After(*session.LastRefreshedAt) {
		session.LastRefreshedAt = &at
	}
	if at.After(session.LastSeenAt) {
		session.LastSeenAt = at
	}
	if accessTokenJTI != "" {
		session.LastAccessTokenJTI = accessTokenJTI
	}
	if deviceID != "" {
		session.DeviceID = deviceID
	}
	if deviceFingerprintHash != "" {
		session.DeviceFingerprintHash = deviceFingerprintHash
	}

	s.sessions[sessionID] = session
	return session, nil
}
