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
type InMemoryRefreshTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*models.RefreshTokenRecord
}

func NewInMemoryRefreshTokenStore() *InMemoryRefreshTokenStore {
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

func (s *InMemoryRefreshTokenStore) FindBySessionID(_ context.Context, sessionID id.SessionID) (*models.RefreshTokenRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
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

// ConsumeRefreshToken marks the refresh token as used if valid.
// It checks for existence, expiry, and usage status.
// Returns the token record and an error if any validation fails.
// IMPORTANT: Returns the record even on ErrAlreadyUsed to enable replay detection.
func (s *InMemoryRefreshTokenStore) ConsumeRefreshToken(_ context.Context, token string, now time.Time) (*models.RefreshTokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.tokens[token]
	if !ok {
		return nil, fmt.Errorf("refresh token not found: %w", sentinel.ErrNotFound)
	}
	if now.After(record.ExpiresAt) {
		return record, fmt.Errorf("refresh token expired: %w", sentinel.ErrExpired)
	}
	if record.Used {
		return record, fmt.Errorf("refresh token already used: %w", sentinel.ErrAlreadyUsed)
	}

	if record.LastRefreshedAt == nil || now.After(*record.LastRefreshedAt) {
		record.LastRefreshedAt = &now
	}
	record.Used = true
	return record, nil
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
