package client

import (
	"context"
	"sync"

	id "credo/pkg/domain"

	"credo/internal/sentinel"
	"credo/internal/tenant/models"
)

// ErrNotFound is returned when a client is not found.
var ErrNotFound = sentinel.ErrNotFound

// InMemory stores clients in memory for the demo environment.
type InMemory struct {
	mu      sync.RWMutex
	clients map[string]*models.Client
	byCode  map[string]*models.Client
}

// NewInMemory creates an in-memory client store.
func NewInMemory() *InMemory {
	return &InMemory{
		clients: make(map[string]*models.Client),
		byCode:  make(map[string]*models.Client),
	}
}

// Create stores a new client.
func (s *InMemory) Create(_ context.Context, c *models.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ID.String()] = c
	s.byCode[c.OAuthClientID] = c
	return nil
}

// Update updates an existing client.
func (s *InMemory) Update(_ context.Context, c *models.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ID.String()] = c
	s.byCode[c.OAuthClientID] = c
	return nil
}

// FindByID retrieves a client by its UUID.
func (s *InMemory) FindByID(_ context.Context, clientID id.ClientID) (*models.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.clients[clientID.String()]; ok {
		return c, nil
	}
	return nil, ErrNotFound
}

// FindByTenantAndID retrieves a client by tenant and ID, enforcing tenant isolation.
func (s *InMemory) FindByTenantAndID(_ context.Context, tenantID id.TenantID, clientID id.ClientID) (*models.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.clients[clientID.String()]; ok {
		if c.TenantID == tenantID {
			return c, nil
		}
	}
	return nil, ErrNotFound
}

// FindByOAuthClientID retrieves a client by its OAuth client_id.
func (s *InMemory) FindByOAuthClientID(_ context.Context, oauthClientID string) (*models.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.byCode[oauthClientID]; ok {
		return c, nil
	}
	return nil, ErrNotFound
}

// CountByTenant returns the number of clients belonging to a specific tenant.
func (s *InMemory) CountByTenant(_ context.Context, tenantID id.TenantID) (int, error) {
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
