package user

import (
	"context"
	"fmt"
	"sync"

	"credo/internal/auth/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"
)

// Error Contract:
// All store methods follow this error pattern:
// - Return ErrNotFound when the requested entity does not exist
// - Return nil for successful operations
// - Return wrapped errors with context for infrastructure failures (future: DB errors, network issues, etc.)
// InMemoryUserStore stores users in memory for tests.
type InMemoryUserStore struct {
	mu    sync.RWMutex
	users map[id.UserID]*models.User
}

func (s *InMemoryUserStore) ListAll(context context.Context) (map[id.UserID]*models.User, error) {
	return s.users, nil
}

// New constructs an empty in-memory user store.
func New() *InMemoryUserStore {
	return &InMemoryUserStore{users: make(map[id.UserID]*models.User)}
}

func (s *InMemoryUserStore) Save(_ context.Context, user *models.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[user.ID] = user
	return nil
}

func (s *InMemoryUserStore) FindByID(_ context.Context, userID id.UserID) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if user, ok := s.users[userID]; ok {
		return user, nil
	}
	return nil, fmt.Errorf("user not found: %w", sentinel.ErrNotFound)
}

func (s *InMemoryUserStore) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, user := range s.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user not found: %w", sentinel.ErrNotFound)
}

// FindOrCreateByTenantAndEmail atomically finds a user by tenant and email or creates it if not found.
// This prevents duplicate user creation in concurrent scenarios while enforcing tenant isolation.
func (s *InMemoryUserStore) FindOrCreateByTenantAndEmail(_ context.Context, tenantID id.TenantID, email string, user *models.User) (*models.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if user already exists for this tenant and email
	for _, existingUser := range s.users {
		if existingUser.Email == email && existingUser.TenantID == tenantID {
			return existingUser, nil
		}
	}

	// User doesn't exist, create it
	s.users[user.ID] = user
	return user, nil
}

func (s *InMemoryUserStore) Delete(_ context.Context, userID id.UserID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; ok {
		delete(s.users, userID)
		return nil
	}
	return fmt.Errorf("user not found: %w", sentinel.ErrNotFound)
}
