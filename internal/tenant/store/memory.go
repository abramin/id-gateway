package store

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"credo/internal/sentinel"
	"credo/internal/tenant/models"
	tenant "credo/internal/tenant/models"
)

// ErrNotFound is returned when a tenant or client is not found.
var ErrNotFound = sentinel.ErrNotFound

// InMemoryTenantStore stores tenants in memory for the demo environment.
type InMemoryTenantStore struct {
	mu      sync.RWMutex
	tenants map[string]*tenant.Tenant
	nameIdx map[string]string
}

func NewInMemoryTenantStore() *InMemoryTenantStore {
	return &InMemoryTenantStore{tenants: make(map[string]*tenant.Tenant), nameIdx: make(map[string]string)}
}

// CreateIfNameAvailable atomically creates the tenant if the name is not already taken (case-insensitive).
func (s *InMemoryTenantStore) CreateIfNameAvailable(_ context.Context, t *tenant.Tenant) error {
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

func (s *InMemoryTenantStore) FindByID(_ context.Context, id uuid.UUID) (*tenant.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if t, ok := s.tenants[id.String()]; ok {
		return t, nil
	}
	return nil, ErrNotFound
}

func (s *InMemoryTenantStore) FindByName(_ context.Context, name string) (*tenant.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if id, ok := s.nameIdx[strings.ToLower(name)]; ok {
		return s.tenants[id], nil
	}
	return nil, ErrNotFound
}

func (s *InMemoryTenantStore) Count(_ context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tenants), nil
}

// InMemoryClientStore stores clients in memory for the demo environment.
type InMemoryClientStore struct {
	mu      sync.RWMutex
	clients map[string]*tenant.Client
	byCode  map[string]*tenant.Client
}

func NewInMemoryClientStore() *InMemoryClientStore {
	return &InMemoryClientStore{
		clients: make(map[string]*tenant.Client),
		byCode:  make(map[string]*tenant.Client),
	}
}

func (s *InMemoryClientStore) Create(_ context.Context, c *tenant.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ID.String()] = c
	s.byCode[c.ClientID] = c
	return nil
}

func (s *InMemoryClientStore) Update(_ context.Context, c *tenant.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ID.String()] = c
	s.byCode[c.ClientID] = c
	return nil
}

func (s *InMemoryClientStore) FindByID(_ context.Context, id uuid.UUID) (*tenant.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.clients[id.String()]; ok {
		return c, nil
	}
	return nil, ErrNotFound
}

func (s *InMemoryClientStore) FindByTenantAndID(_ context.Context, tenantID uuid.UUID, id uuid.UUID) (*tenant.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.clients[id.String()]; ok {
		if c.TenantID == tenantID {
			return c, nil
		}
	}
	return nil, ErrNotFound
}

func (s *InMemoryClientStore) FindByClientID(_ context.Context, clientID string) (*tenant.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.byCode[clientID]; ok {
		return c, nil
	}
	return nil, ErrNotFound
}

func (s *InMemoryClientStore) CountByTenant(_ context.Context, tenantID uuid.UUID) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, c := range s.clients {
		if c.TenantID == tenantID {
			count++
		}
	}
	return count, nil
}

// SeedBootstrapTenant creates a default tenant and client for backward compatibility.
func SeedBootstrapTenant(ts *InMemoryTenantStore, cs *InMemoryClientStore) (*tenant.Tenant, *tenant.Client) {
	now := time.Now()
	t := &tenant.Tenant{ID: uuid.New(), Name: "default", Status: string(models.TenantStatusActive), CreatedAt: now}
	_ = ts.CreateIfNameAvailable(context.Background(), t)

	redirectURIs := []string{
		"http://localhost:3000/callback",
		"http://localhost",
	}

	c := &tenant.Client{
		ID:            uuid.New(),
		TenantID:      t.ID,
		Name:          "default-client",
		ClientID:      "test-client",
		RedirectURIs:  redirectURIs,
		AllowedGrants: []string{"authorization_code", "refresh_token"},
		AllowedScopes: []string{"openid", "profile"},
		Status:        string(models.ClientStatusActive),
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	_ = cs.Create(context.Background(), c)
	return t, c
}
