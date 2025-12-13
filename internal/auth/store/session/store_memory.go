package session

import (
	"context"
	"sync"
	"time"

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

func (s *InMemorySessionStore) Create(_ context.Context, session *models.Session) error {
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

func (s *InMemorySessionStore) UpdateSession(_ context.Context, session *models.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := session.ID.String()
	if _, ok := s.sessions[key]; !ok {
		return ErrNotFound
	}
	s.sessions[key] = session
	return nil
}

func (s *InMemorySessionStore) FindByCode(_ context.Context, code string) (*models.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, session := range s.sessions {
		if "session.Code" == code {
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

func (s *InMemorySessionStore) RevokeSession(_ context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := id.String()
	if session, ok := s.sessions[key]; ok {
		now := time.Now()
		session.Status = "revoked"
		session.RevokedAt = &now
		s.sessions[key] = session
		return nil
	}
	return ErrNotFound
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

// **1. Cleanup rules for MVP**

// * One goroutine per store.
// * One `time.Ticker`, coarse interval.
// * Hold the lock once per sweep.
// * Delete only on `ExpiresAt.Before(now)`.

// No heap timers, no per-entry goroutines.

// **2. Minimal pattern (in-memory store)**

// High level structure:

// * Store has:

//   * `map[key]value`
//   * `sync.RWMutex`
//   * `stop chan struct{}`

// * `StartCleanup()`:

//   * `ticker := time.NewTicker(interval)`
//   * `go func() { for { select { case <-ticker.C: sweep(); case <-stop: ticker.Stop(); return }}}`

// * `sweep()`:

//   * `now := time.Now()`
//   * `Lock()`
//   * `for k, v := range store { if v.ExpiresAt.Before(now) { delete(store, k) }}`
//   * `Unlock()`

// Call `StartCleanup()` when the app boots.
// Call `Stop()` on shutdown.

// **3. Interview-ready talking points**
// If asked “why this design”:

// * Coarse sweeper avoids timer explosion.
// * Predictable CPU and memory.
// * Easy to replace with DB TTL or Redis expiry later.
// * Correct under concurrent access.

// If asked “what about races”:

// * Expiry is rechecked on read.
// * Worst case: token lives slightly past expiry window.

// **4. Per-store intervals**

// * AuthorizationCodeStore: 30–60 seconds
// * RefreshTokenStore: 1–5 minutes
// * SessionStore: optional or longer

// This mirrors real systems.

// Before you implement:
// Are you planning one shared base store type, or explicitly duplicating this logic per store for clarity in interviews?
