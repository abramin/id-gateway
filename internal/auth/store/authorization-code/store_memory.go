package authorizationcode

import (
	"context"
	"fmt"
	"sync"
	"time"

	"credo/internal/auth/models"
	"credo/pkg/platform/sentinel"
)


// Error Contract:
// All store methods follow this error pattern:
// - Return ErrNotFound when the requested entity does not exist
// - Return nil for successful operations
// - Return wrapped errors with context for infrastructure failures (future: DB errors, network issues, etc.)
//

// InMemoryAuthorizationCodeStore stores authorization codes in memory for tests/dev.
type InMemoryAuthorizationCodeStore struct {
	mu        sync.RWMutex
	authCodes map[string]*models.AuthorizationCodeRecord
}

// New constructs an empty in-memory auth code store.
func New() *InMemoryAuthorizationCodeStore {
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
	return nil, fmt.Errorf("authorization code not found: %w", sentinel.ErrNotFound)
}

func (s *InMemoryAuthorizationCodeStore) MarkUsed(_ context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.authCodes[code]
	if !ok {
		return fmt.Errorf("authorization code not found: %w", sentinel.ErrNotFound)
	}
	record.MarkUsed()
	return nil
}


// DeleteExpiredCodes removes all authorization codes that have expired as of the given time.
// The time parameter is injected for testability (no hidden time.Now() calls).
func (s *InMemoryAuthorizationCodeStore) DeleteExpiredCodes(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	deletedCount := 0
	for code, record := range s.authCodes {
		if record.ExpiresAt.Before(now) {
			delete(s.authCodes, code)
			deletedCount++
		}
	}
	return deletedCount, nil
}

// Execute atomically validates and mutates an auth code under lock.
// The validate callback runs first; if it returns an error (typically a domain error),
// that error is returned as-is without translation, along with the record (for replay detection).
// The mutate callback applies changes to the record after validation passes.
// Returns sentinel.ErrNotFound if the code doesn't exist.
func (s *InMemoryAuthorizationCodeStore) Execute(_ context.Context, code string, validate func(*models.AuthorizationCodeRecord) error, mutate func(*models.AuthorizationCodeRecord)) (*models.AuthorizationCodeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.authCodes[code]
	if !ok {
		return nil, sentinel.ErrNotFound
	}

	if err := validate(record); err != nil {
		return record, err // Domain error from callback - return record for replay detection
	}

	mutate(record)
	return record, nil
}
