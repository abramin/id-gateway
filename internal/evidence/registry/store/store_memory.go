package store

import (
	"context"
	"errors"
	"sync"
	"time"

	"credo/internal/evidence/registry/models"
)

type cachedCitizen struct {
	record   models.CitizenRecord
	storedAt time.Time
}

type cachedSanction struct {
	record   models.SanctionsRecord
	storedAt time.Time
}

type InMemoryCache struct {
	mu        sync.RWMutex
	citizens  map[string]cachedCitizen
	sanctions map[string]cachedSanction
	cacheTTL  time.Duration
}

var ErrNotFound = errors.New("not found") // TODO: move to a more appropriate package

func NewInMemoryCache(cacheTTL time.Duration) *InMemoryCache {
	return &InMemoryCache{
		citizens:  make(map[string]cachedCitizen),
		sanctions: make(map[string]cachedSanction),
		cacheTTL:  cacheTTL,
	}
}

func (c *InMemoryCache) SaveCitizen(_ context.Context, record *models.CitizenRecord) error {
	if record == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.citizens[record.NationalID] = cachedCitizen{record: *record, storedAt: time.Now()}
	return nil
}

func (c *InMemoryCache) FindCitizen(_ context.Context, nationalID string) (*models.CitizenRecord, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if cached, ok := c.citizens[nationalID]; ok {
		if time.Since(cached.storedAt) < c.cacheTTL {
			return &cached.record, nil
		}
	}
	return nil, ErrNotFound
}

func (c *InMemoryCache) SaveSanction(_ context.Context, record *models.SanctionsRecord) error {
	if record == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sanctions[record.NationalID] = cachedSanction{record: *record, storedAt: time.Now()}
	return nil
}

func (c *InMemoryCache) FindSanction(_ context.Context, nationalID string) (*models.SanctionsRecord, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if cached, ok := c.sanctions[nationalID]; ok {
		if time.Since(cached.storedAt) < c.cacheTTL {
			return &cached.record, nil
		}
	}
	return nil, ErrNotFound
}
