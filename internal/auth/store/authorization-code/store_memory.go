package authorizationcode

import (
	"context"
	"sync"
	"time"

	"credo/internal/auth/models"
	dErrors "credo/pkg/domain-errors"

	"github.com/google/uuid"
)

// ErrNotFound is returned when a requested record is not found in the store.
// Services should check for this error using errors.Is(err, store.ErrNotFound).
var ErrNotFound = dErrors.New(dErrors.CodeNotFound, "record not found")
var ErrAuthCodeUsed = dErrors.New(dErrors.CodeUnauthorized, "authorization code already used")
var ErrAuthCodeExpired = dErrors.New(dErrors.CodeUnauthorized, "authorization code expired")

// Error Contract:
// All store methods follow this error pattern:
// - Return ErrNotFound when the requested entity does not exist
// - Return nil for successful operations
// - Return wrapped errors with context for infrastructure failures (future: DB errors, network issues, etc.)
//
// In-memory stores keep the initial implementation lightweight and testable.
// They intentionally favor clarity over performance.

type InMemoryAuthorizationCodeStore struct {
	mu        sync.RWMutex
	authCodes map[string]*models.AuthorizationCodeRecord
}

func NewInMemoryAuthorizationCodeStore() *InMemoryAuthorizationCodeStore {
	return &InMemoryAuthorizationCodeStore{
		authCodes: make(map[string]*models.AuthorizationCodeRecord),
	}
}

func (s *InMemoryAuthorizationCodeStore) Create(_ context.Context, authCode *models.AuthorizationCodeRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authCodes[authCode.Code] = authCode
	return nil
}

func (s *InMemoryAuthorizationCodeStore) FindByCode(_ context.Context, code string) (*models.AuthorizationCodeRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if authCode, ok := s.authCodes[code]; ok {
		return authCode, nil
	}
	return nil, ErrNotFound
}

func (s *InMemoryAuthorizationCodeStore) FindByID(_ context.Context, id uuid.UUID) (*models.AuthorizationCodeRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if authCode, ok := s.authCodes[id.String()]; ok {
		return authCode, nil
	}
	return nil, ErrNotFound
}

func (s *InMemoryAuthorizationCodeStore) Delete(_ context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.authCodes[code]; ok {
		delete(s.authCodes, code)
		return nil
	}
	return ErrNotFound
}

func (s *InMemoryAuthorizationCodeStore) MarkUsed(_ context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if record, ok := s.authCodes[code]; ok {
		record.Used = true
		return nil
	}
	return ErrNotFound
}

func (s *InMemoryAuthorizationCodeStore) ConsumeAuthCode(_ context.Context, code string, redirectURI string, now time.Time) (*models.AuthorizationCodeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.authCodes[code]
	if !ok {
		return nil, ErrNotFound
	}
	if record.RedirectURI != redirectURI {
		return record, dErrors.New(dErrors.CodeBadRequest, "redirect_uri mismatch")
	}
	if now.After(record.ExpiresAt) {
		return record, ErrAuthCodeExpired
	}
	if record.Used {
		return record, ErrAuthCodeUsed
	}

	record.Used = true
	return record, nil
}

func (s *InMemoryAuthorizationCodeStore) DeleteExpiredCodes(_ context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	deletedCount := 0
	for code, record := range s.authCodes {
		if record.ExpiresAt.Before(now) {
			delete(s.authCodes, code)
			deletedCount++
		}
	}
	return deletedCount, nil
}

// Token Cleanup Strategy

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
