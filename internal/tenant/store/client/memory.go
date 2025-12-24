package client

import (
	"context"
	"sync"

	"credo/internal/tenant/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"
)

type InMemory struct {
	mu          sync.RWMutex
	clients     map[id.ClientID]*models.Client
	byCode      map[string]*models.Client
	tenantCount map[id.TenantID]int // secondary index for O(1) CountByTenant
}

func NewInMemory() *InMemory {
	return &InMemory{
		clients:     make(map[id.ClientID]*models.Client),
		byCode:      make(map[string]*models.Client),
		tenantCount: make(map[id.TenantID]int),
	}
}

func (s *InMemory) Create(_ context.Context, c *models.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ID] = c
	s.byCode[c.OAuthClientID] = c
	s.tenantCount[c.TenantID]++
	return nil
}

func (s *InMemory) Update(_ context.Context, c *models.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ID] = c
	s.byCode[c.OAuthClientID] = c
	return nil
}

func (s *InMemory) FindByID(_ context.Context, clientID id.ClientID) (*models.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.clients[clientID]; ok {
		return c, nil
	}
	return nil, sentinel.ErrNotFound
}

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

func (s *InMemory) FindByOAuthClientID(_ context.Context, oauthClientID string) (*models.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.byCode[oauthClientID]; ok {
		return c, nil
	}
	return nil, sentinel.ErrNotFound
}

func (s *InMemory) CountByTenant(_ context.Context, tenantID id.TenantID) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tenantCount[tenantID], nil
}
