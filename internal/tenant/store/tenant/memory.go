package tenant

import (
	"context"
	"fmt"
	"strings"
	"sync"

	id "credo/pkg/domain"

	"credo/internal/sentinel"
	"credo/internal/tenant/models"
)

// ErrNotFound is returned when a tenant is not found.
var ErrNotFound = sentinel.ErrNotFound

// InMemory stores tenants in memory for the demo environment.
type InMemory struct {
	mu      sync.RWMutex
	tenants map[string]*models.Tenant
	nameIdx map[string]string
}

// NewInMemory creates an in-memory tenant store.
func NewInMemory() *InMemory {
	return &InMemory{
		tenants: make(map[string]*models.Tenant),
		nameIdx: make(map[string]string),
	}
}

// CreateIfNameAvailable atomically creates the tenant if the name is not already taken (case-insensitive).
func (s *InMemory) CreateIfNameAvailable(_ context.Context, t *models.Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	lower := strings.ToLower(t.Name)
	if _, exists := s.nameIdx[lower]; exists {
		return fmt.Errorf("tenant name must be unique: %w", sentinel.ErrAlreadyUsed)
	}
	key := t.ID.String()
	s.tenants[key] = t
	s.nameIdx[lower] = key
	return nil
}

// FindByID retrieves a tenant by its UUID.
func (s *InMemory) FindByID(_ context.Context, tenantID id.TenantID) (*models.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if t, ok := s.tenants[tenantID.String()]; ok {
		return t, nil
	}
	return nil, ErrNotFound
}

// FindByName retrieves a tenant by name (case-insensitive).
func (s *InMemory) FindByName(_ context.Context, name string) (*models.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if id, ok := s.nameIdx[strings.ToLower(name)]; ok {
		return s.tenants[id], nil
	}
	return nil, ErrNotFound
}

// Count returns the total number of tenants.
func (s *InMemory) Count(_ context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tenants), nil
}
