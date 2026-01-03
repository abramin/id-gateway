package tenant

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"credo/internal/tenant/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"
)

// InMemory stores tenants in memory for tests.
type InMemory struct {
	mu      sync.RWMutex
	tenants map[id.TenantID]*models.Tenant
	nameIdx map[string]id.TenantID
}

// NewInMemory creates an in-memory tenant store.
func NewInMemory() *InMemory {
	return &InMemory{
		tenants: make(map[id.TenantID]*models.Tenant),
		nameIdx: make(map[string]id.TenantID),
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
	s.tenants[t.ID] = t
	s.nameIdx[lower] = t.ID
	return nil
}

// FindByID retrieves a tenant by its UUID.
func (s *InMemory) FindByID(_ context.Context, tenantID id.TenantID) (*models.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if t, ok := s.tenants[tenantID]; ok {
		return t, nil
	}
	return nil, sentinel.ErrNotFound
}

// FindByName retrieves a tenant by name (case-insensitive).
func (s *InMemory) FindByName(_ context.Context, name string) (*models.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if tenantID, ok := s.nameIdx[strings.ToLower(name)]; ok {
		return s.tenants[tenantID], nil
	}
	return nil, sentinel.ErrNotFound
}

// Count returns the total number of tenants.
func (s *InMemory) Count(_ context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tenants), nil
}

// Update updates an existing tenant. Returns ErrNotFound if tenant doesn't exist.
func (s *InMemory) Update(_ context.Context, t *models.Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tenants[t.ID]; !exists {
		return sentinel.ErrNotFound
	}
	s.tenants[t.ID] = t
	return nil
}

// Execute atomically validates and mutates a tenant under lock.
func (s *InMemory) Execute(_ context.Context, tenantID id.TenantID, validate func(*models.Tenant) error, mutate func(*models.Tenant)) (*models.Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenant, exists := s.tenants[tenantID]
	if !exists {
		return nil, sentinel.ErrNotFound
	}

	if err := validate(tenant); err != nil {
		return nil, err
	}

	mutate(tenant)
	s.tenants[tenantID] = tenant
	return tenant, nil
}
