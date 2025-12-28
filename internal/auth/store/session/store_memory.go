package session

import (
	"context"
	"fmt"
	"maps"
	"strings"
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

func (s *InMemorySessionStore) RevokeSession(_ context.Context, sessionID id.SessionID) error {
	return s.RevokeSessionIfActive(context.Background(), sessionID, time.Now())
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

// translateSessionError converts domain errors from Session.ValidateForAdvance to sentinel errors.
// Store boundary contract: return sentinel errors for infrastructure/store callers.
func translateSessionError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "expired"):
		return fmt.Errorf("%s: %w", msg, sentinel.ErrExpired)
	case strings.Contains(msg, "revoked"):
		return ErrSessionRevoked
	default:
		return fmt.Errorf("%s: %w", msg, sentinel.ErrInvalidState)
	}
}

// validateForAdvance calls the domain validation method and translates errors to sentinel errors.
// allowPending=true permits pending_consent status (for code exchange activation).
func validateForAdvance(session *models.Session, clientID id.ClientID, at time.Time, allowPending bool) error {
	if err := session.ValidateForAdvance(clientID, at, allowPending); err != nil {
		return translateSessionError(err)
	}
	return nil
}

// AdvanceLastSeen updates the session's last seen time and other optional fields.
// It validates the session using domain logic, then applies updates via domain methods.
// Errors are returned as sentinel errors per store boundary contract.
func (s *InMemorySessionStore) AdvanceLastSeen(_ context.Context, sessionID id.SessionID, clientID id.ClientID, at time.Time, accessTokenJTI string, activate bool, deviceID string, deviceFingerprintHash string) (*models.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session not found: %w", sentinel.ErrNotFound)
	}

	// Validate using domain checks, return sentinel errors per store contract
	if err := validateForAdvance(session, clientID, at, true); err != nil {
		return nil, err
	}

	// Apply updates using domain methods
	session.RecordActivity(at)
	if activate {
		session.Activate()
	}
	session.ApplyTokenJTI(accessTokenJTI)
	session.ApplyDeviceInfo(deviceID, deviceFingerprintHash)

	s.sessions[sessionID] = session
	return session, nil
}

// AdvanceLastRefreshed updates the session's refresh timestamp and activity time.
// Errors are returned as sentinel errors per store boundary contract.
func (s *InMemorySessionStore) AdvanceLastRefreshed(_ context.Context, sessionID id.SessionID, clientID id.ClientID, at time.Time, accessTokenJTI string, deviceID string, deviceFingerprintHash string) (*models.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session not found: %w", sentinel.ErrNotFound)
	}

	// Validate using domain checks, return sentinel errors per store contract
	if err := validateForAdvance(session, clientID, at, false); err != nil {
		return nil, err
	}

	// Apply updates using domain methods
	session.RecordRefresh(at)
	session.ApplyTokenJTI(accessTokenJTI)
	session.ApplyDeviceInfo(deviceID, deviceFingerprintHash)

	s.sessions[sessionID] = session
	return session, nil
}
