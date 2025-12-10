package registry

import (
	"context"
	"sync"
	"time"

	"credo/internal/platform/config"
)

type cachedCitizen struct {
	record   CitizenRecord
	storedAt time.Time
}

type cachedSanction struct {
	record   SanctionsRecord
	storedAt time.Time
}

type InMemoryCache struct {
	mu        sync.RWMutex
	citizens  map[string]cachedCitizen
	sanctions map[string]cachedSanction
}

func NewInMemoryCache() *InMemoryCache {
	return &InMemoryCache{
		citizens:  make(map[string]cachedCitizen),
		sanctions: make(map[string]cachedSanction),
	}
}

func (c *InMemoryCache) SaveCitizen(_ context.Context, record CitizenRecord) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.citizens[record.NationalID] = cachedCitizen{record: record, storedAt: time.Now()}
	return nil
}

func (c *InMemoryCache) FindCitizen(_ context.Context, nationalID string) (CitizenRecord, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if cached, ok := c.citizens[nationalID]; ok {
		if time.Since(cached.storedAt) < config.RegistryCacheTTL {
			return cached.record, nil
		}
	}
	return CitizenRecord{}, ErrNotFound
}

func (c *InMemoryCache) SaveSanction(_ context.Context, record SanctionsRecord) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sanctions[record.NationalID] = cachedSanction{record: record, storedAt: time.Now()}
	return nil
}

func (c *InMemoryCache) FindSanction(_ context.Context, nationalID string) (SanctionsRecord, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if cached, ok := c.sanctions[nationalID]; ok {
		if time.Since(cached.storedAt) < config.RegistryCacheTTL {
			return cached.record, nil
		}
	}
	return SanctionsRecord{}, ErrNotFound
}
