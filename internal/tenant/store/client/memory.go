package client

import (
	"context"
	"sync"

	id "credo/pkg/domain"

	"credo/internal/tenant/models"
	"credo/pkg/platform/sentinel"
)

var ErrNotFound = sentinel.ErrNotFound

type InMemory struct {
	mu      sync.RWMutex
	clients map[id.ClientID]*models.Client
	byCode  map[string]*models.Client
}

func NewInMemory() *InMemory {
	return &InMemory{
		clients: make(map[id.ClientID]*models.Client),
		byCode:  make(map[string]*models.Client),
	}
}

func (s *InMemory) Create(_ context.Context, c *models.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ID] = c
	s.byCode[c.OAuthClientID] = c
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
	return nil, ErrNotFound
}

func (s *InMemory) FindByTenantAndID(_ context.Context, tenantID id.TenantID, clientID id.ClientID) (*models.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.clients[clientID]; ok {
		if c.TenantID == tenantID {
			return c, nil
		}
	}
	return nil, ErrNotFound
}

func (s *InMemory) FindByOAuthClientID(_ context.Context, oauthClientID string) (*models.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.byCode[oauthClientID]; ok {
		return c, nil
	}
	return nil, ErrNotFound
}

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
