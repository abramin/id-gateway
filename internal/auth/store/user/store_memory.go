package user

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"

	"credo/internal/auth/models"
	"credo/internal/sentinel"
)

// ErrNotFound is returned when a requested record is not found in the store.
// Services should check for this error using errors.Is(err, store.ErrNotFound).
var ErrNotFound = sentinel.ErrNotFound

// Error Contract:
// All store methods follow this error pattern:
// - Return ErrNotFound when the requested entity does not exist
// - Return nil for successful operations
// - Return wrapped errors with context for infrastructure failures (future: DB errors, network issues, etc.)
//
// In-memory stores keep the initial implementation lightweight and testable.
// They intentionally favor clarity over performance.
type InMemoryUserStore struct {
	mu    sync.RWMutex
	users map[string]*models.User
}

func (s *InMemoryUserStore) ListAll(context context.Context) (map[string]*models.User, error) {
	return s.users, nil
}

func NewInMemoryUserStore() *InMemoryUserStore {
	return &InMemoryUserStore{users: make(map[string]*models.User)}
}

func (s *InMemoryUserStore) Save(_ context.Context, user *models.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[user.ID.String()] = user
	return nil
}

func (s *InMemoryUserStore) FindByID(_ context.Context, id uuid.UUID) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if user, ok := s.users[id.String()]; ok {
		return user, nil
	}
	return nil, fmt.Errorf("user not found: %w", ErrNotFound)
}

func (s *InMemoryUserStore) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, user := range s.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user not found: %w", ErrNotFound)
}

// FindOrCreateByTenantAndEmail atomically finds a user by tenant and email or creates it if not found.
// This prevents duplicate user creation in concurrent scenarios while enforcing tenant isolation.
func (s *InMemoryUserStore) FindOrCreateByTenantAndEmail(_ context.Context, tenantID uuid.UUID, email string, user *models.User) (*models.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if user already exists for this tenant and email
	for _, existingUser := range s.users {
		if existingUser.Email == email && existingUser.TenantID == tenantID {
			return existingUser, nil
		}
	}

	// User doesn't exist, create it
	s.users[user.ID.String()] = user
	return user, nil
}

func (s *InMemoryUserStore) Delete(ctx context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := id.String()
	if _, ok := s.users[key]; ok {
		delete(s.users, key)
		return nil
	}
	return fmt.Errorf("user not found: %w", ErrNotFound)
}
