package refreshtoken

import (
	"context"
	"fmt"
	"sync"
	"time"

	"credo/internal/auth/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"
)

// Error Contract:
// All store methods follow this error pattern:
// - Return ErrNotFound when the requested entity does not exist
// - Return nil for successful operations
// - Return wrapped errors with context for infrastructure failures (future: DB errors, network issues, etc.)
// InMemoryRefreshTokenStore stores refresh tokens in memory for tests.
type InMemoryRefreshTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*models.RefreshTokenRecord
}

// New constructs an empty in-memory refresh token store.
func New() *InMemoryRefreshTokenStore {
	return &InMemoryRefreshTokenStore{tokens: make(map[string]*models.RefreshTokenRecord)}
}

func (s *InMemoryRefreshTokenStore) Create(_ context.Context, token *models.RefreshTokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token.Token] = token
	return nil
}

func (s *InMemoryRefreshTokenStore) Find(_ context.Context, token string) (*models.RefreshTokenRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if record, ok := s.tokens[token]; ok {
		return record, nil
	}
	return nil, fmt.Errorf("refresh token not found: %w", sentinel.ErrNotFound)
}

func (s *InMemoryRefreshTokenStore) FindBySessionID(_ context.Context, sessionID id.SessionID, now time.Time) (*models.RefreshTokenRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var best *models.RefreshTokenRecord
	for _, token := range s.tokens {
		if token.SessionID != sessionID {
			continue
		}
		if token.Used {
			continue
		}
		if !token.ExpiresAt.IsZero() && token.ExpiresAt.Before(now) {
			continue
		}
		if best == nil || token.CreatedAt.After(best.CreatedAt) {
			best = token
		}
	}
	if best == nil {
		return nil, fmt.Errorf("refresh token not found: %w", sentinel.ErrNotFound)
	}
	return best, nil
}

func (s *InMemoryRefreshTokenStore) DeleteBySessionID(_ context.Context, sessionID id.SessionID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for key, token := range s.tokens {
		if token.SessionID == sessionID {
			delete(s.tokens, key)
			found = true
		}
	}
	if !found {
		return sentinel.ErrNotFound
	}
	return nil
}

// DeleteExpiredTokens removes all refresh tokens that have expired as of the given time.
// The time parameter is injected for testability (no hidden time.Now() calls).
func (s *InMemoryRefreshTokenStore) DeleteExpiredTokens(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	deletedCount := 0
	for key, token := range s.tokens {
		if token.ExpiresAt.Before(now) {
			delete(s.tokens, key)
			deletedCount++
		}
	}
	return deletedCount, nil
}

func (s *InMemoryRefreshTokenStore) DeleteUsedTokens(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	deletedCount := 0
	for key, token := range s.tokens {
		if token.Used {
			delete(s.tokens, key)
			deletedCount++
		}
	}
	return deletedCount, nil
}

// Execute atomically validates and mutates a refresh token under lock.
// The validate callback runs first; if it returns an error (typically a domain error),
// that error is returned as-is without translation, along with the record (for replay detection).
// The mutate callback applies changes to the record after validation passes.
// Returns sentinel.ErrNotFound if the token doesn't exist.
func (s *InMemoryRefreshTokenStore) Execute(_ context.Context, token string, validate func(*models.RefreshTokenRecord) error, mutate func(*models.RefreshTokenRecord)) (*models.RefreshTokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.tokens[token]
	if !ok {
		return nil, sentinel.ErrNotFound
	}

	if err := validate(record); err != nil {
		return record, err // Domain error from callback - return record for replay detection
	}

	mutate(record)
	return record, nil
}
