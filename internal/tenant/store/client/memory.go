package client

import (
	"context"
	"sync"

	"credo/internal/tenant/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"
)

// InMemory stores clients in memory for tests.
// Maintains secondary indexes for efficient OAuth client_id lookups and tenant counts.
type InMemory struct {
	mu          sync.RWMutex
	clients     map[id.ClientID]*models.Client
	byCode      map[string]*models.Client
	tenantCount map[id.TenantID]int // secondary index for O(1) CountByTenant
}

// NewInMemory creates an in-memory client store with initialized indexes.
func NewInMemory() *InMemory {
	return &InMemory{
		clients:     make(map[id.ClientID]*models.Client),
		byCode:      make(map[string]*models.Client),
		tenantCount: make(map[id.TenantID]int),
	}
}

// Create persists a new client and updates secondary indexes.
// Increments the tenant's client count for efficient aggregation queries.
func (s *InMemory) Create(_ context.Context, c *models.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ID] = c
	s.byCode[c.OAuthClientID] = c
	s.tenantCount[c.TenantID]++
	return nil
}

// Update persists changes to an existing client.
// Does not modify tenant counts (client cannot change tenants).
func (s *InMemory) Update(_ context.Context, c *models.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ID] = c
	s.byCode[c.OAuthClientID] = c
	return nil
}

// FindByID retrieves a client by its internal UUID.
// Returns sentinel.ErrNotFound if the client does not exist.
func (s *InMemory) FindByID(_ context.Context, clientID id.ClientID) (*models.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.clients[clientID]; ok {
		return c, nil
	}
	return nil, sentinel.ErrNotFound
}

// FindByTenantAndID retrieves a client scoped to a specific tenant.
// Returns sentinel.ErrNotFound if client doesn't exist or belongs to a different tenant.
func (s *InMemory) FindByTenantAndID(_ context.Context, tenantID id.TenantID, clientID id.ClientID) (*models.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.clients[clientID]; ok {
		if c.TenantID == tenantID {
			return c, nil
		}
	}
	return nil, sentinel.ErrNotFound
}

// FindByOAuthClientID retrieves a client by its OAuth client_id (used in OAuth flows).
// Returns sentinel.ErrNotFound if no client has the given OAuth client_id.
func (s *InMemory) FindByOAuthClientID(_ context.Context, oauthClientID string) (*models.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.byCode[oauthClientID]; ok {
		return c, nil
	}
	return nil, sentinel.ErrNotFound
}

// CountByTenant returns the number of clients registered under a tenant.
// Uses a pre-computed index for O(1) performance.
func (s *InMemory) CountByTenant(_ context.Context, tenantID id.TenantID) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tenantCount[tenantID], nil
}

// Execute atomically validates and mutates a client under lock.
func (s *InMemory) Execute(_ context.Context, clientID id.ClientID, validate func(*models.Client) error, mutate func(*models.Client)) (*models.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	client, exists := s.clients[clientID]
	if !exists {
		return nil, sentinel.ErrNotFound
	}

	if err := validate(client); err != nil {
		return nil, err
	}

	mutate(client)
	s.clients[clientID] = client
	s.byCode[client.OAuthClientID] = client
	return client, nil
}
