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
	return nil, fmt.Errorf("authorization code not found: %w", sentinel.ErrNotFound)
}

func (s *InMemoryAuthorizationCodeStore) MarkUsed(_ context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if record, ok := s.authCodes[code]; ok {
		record.Used = true
		return nil
	}
	return fmt.Errorf("authorization code not found: %w", sentinel.ErrNotFound)
}

// ConsumeAuthCode marks the authorization code as used if valid.
// It checks for existence, redirect URI match, expiry, and usage status.
// Returns the code record and an error if any validation fails.
func (s *InMemoryAuthorizationCodeStore) ConsumeAuthCode(_ context.Context, code string, redirectURI string, now time.Time) (*models.AuthorizationCodeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.authCodes[code]
	if !ok {
		return nil, fmt.Errorf("authorization code not found: %w", sentinel.ErrNotFound)
	}
	if record.RedirectURI != redirectURI {
		return record, fmt.Errorf("redirect_uri mismatch: %w", sentinel.ErrInvalidState)
	}
	if now.After(record.ExpiresAt) {
		return record, fmt.Errorf("authorization code expired: %w", sentinel.ErrExpired)
	}
	if record.Used {
		return record, fmt.Errorf("authorization code already used: %w", sentinel.ErrAlreadyUsed)
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
