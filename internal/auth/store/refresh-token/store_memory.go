package refreshtoken

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"credo/internal/auth/models"
	"credo/internal/sentinel"
)

// ErrNotFound is returned when a requested record is not found in the store.
// Services should check for this error using errors.Is(err, store.ErrNotFound).
var ErrNotFound = sentinel.ErrNotFound
var ErrRefreshTokenUsed = sentinel.ErrAlreadyUsed
var ErrRefreshTokenExpired = sentinel.ErrExpired

// Error Contract:
// All store methods follow this error pattern:
// - Return ErrNotFound when the requested entity does not exist
// - Return nil for successful operations
// - Return wrapped errors with context for infrastructure failures (future: DB errors, network issues, etc.)
//
// In-memory stores keep the initial implementation lightweight and testable.
// They intentionally favor clarity over performance.
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
	return nil, fmt.Errorf("refresh token not found: %w", ErrNotFound)
}

func (s *InMemoryRefreshTokenStore) FindBySessionID(_ context.Context, id uuid.UUID) (*models.RefreshTokenRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	var best *models.RefreshTokenRecord
	for _, token := range s.tokens {
		if token.SessionID != id {
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
		return nil, fmt.Errorf("refresh token not found: %w", ErrNotFound)
	}
	return best, nil
}

func (s *InMemoryRefreshTokenStore) DeleteBySessionID(ctx context.Context, sessionID uuid.UUID) error {
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
		return ErrNotFound
	}
	return nil
}

func (s *InMemoryRefreshTokenStore) ConsumeRefreshToken(_ context.Context, token string, now time.Time) (*models.RefreshTokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.tokens[token]
	if !ok {
		return nil, fmt.Errorf("refresh token not found: %w", ErrNotFound)
	}
	if now.After(record.ExpiresAt) {
		return nil, fmt.Errorf("refresh token expired: %w", ErrRefreshTokenExpired)
	}
	if record.Used {
		return nil, fmt.Errorf("refresh token already used: %w", ErrRefreshTokenUsed)
	}

	if record.LastRefreshedAt == nil || now.After(*record.LastRefreshedAt) {
		record.LastRefreshedAt = &now
	}
	record.Used = true
	return record, nil
}

func (s *InMemoryRefreshTokenStore) DeleteExpiredTokens(_ context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
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
