package quota

import (
	"context"
	"sync"
	"time"

	c "credo/internal/ratelimit/config"
	"credo/internal/ratelimit/models"
	id "credo/pkg/domain"
)

type InMemoryQuotaStore struct {
	mu     sync.RWMutex
	quotas map[id.APIKeyID]*models.APIKeyQuota
	config *c.Config
}

func New(config *c.Config) *InMemoryQuotaStore {
	return &InMemoryQuotaStore{
		quotas: make(map[id.APIKeyID]*models.APIKeyQuota),
		config: config,
	}
}

func (s *InMemoryQuotaStore) GetQuota(_ context.Context, apiKeyID id.APIKeyID) (quota *models.APIKeyQuota, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if quota, exists := s.quotas[apiKeyID]; exists {
		return quota, nil
	}
	return nil, nil
}

func (s *InMemoryQuotaStore) IncrementUsage(_ context.Context, apiKeyID id.APIKeyID, count int) (quota *models.APIKeyQuota, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	quota, exists := s.quotas[apiKeyID]
	if !exists {
		limits := s.config.QuotaTiers[models.QuotaTierFree]
		quota = &models.APIKeyQuota{
			APIKeyID:       apiKeyID,
			Tier:           models.QuotaTierFree,
			MonthlyLimit:   limits.MonthlyRequests,
			CurrentUsage:   0,
			OverageAllowed: limits.OverageAllowed,
			PeriodStart:    time.Now(),
			PeriodEnd:      time.Now().AddDate(0, 1, 0),
		}
		s.quotas[apiKeyID] = quota
	}
	quota.CurrentUsage += count
	return quota, nil
}

// ResetQuota resets the usage counter for an API key (PRD-017 FR-5)
func (s *InMemoryQuotaStore) ResetQuota(_ context.Context, apiKeyID id.APIKeyID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if quota, exists := s.quotas[apiKeyID]; exists {
		quota.CurrentUsage = 0
		quota.PeriodStart = time.Now()
		quota.PeriodEnd = time.Now().AddDate(0, 1, 0)
	}
	return nil
}

// ListQuotas returns all quota records (PRD-017 FR-5)
func (s *InMemoryQuotaStore) ListQuotas(_ context.Context) ([]*models.APIKeyQuota, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*models.APIKeyQuota, 0, len(s.quotas))
	for _, quota := range s.quotas {
		result = append(result, quota)
	}
	return result, nil
}

// UpdateTier changes the tier for an API key (PRD-017 FR-5)
func (s *InMemoryQuotaStore) UpdateTier(_ context.Context, apiKeyID id.APIKeyID, tier models.QuotaTier) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	quota, exists := s.quotas[apiKeyID]
	if !exists {
		// Create new quota with the specified tier
		limits := s.config.QuotaTiers[tier]
		quota = &models.APIKeyQuota{
			APIKeyID:       apiKeyID,
			Tier:           tier,
			MonthlyLimit:   limits.MonthlyRequests,
			CurrentUsage:   0,
			OverageAllowed: limits.OverageAllowed,
			PeriodStart:    time.Now(),
			PeriodEnd:      time.Now().AddDate(0, 1, 0),
		}
		s.quotas[apiKeyID] = quota
		return nil
	}

	// Update existing quota
	limits := s.config.QuotaTiers[tier]
	quota.Tier = tier
	quota.MonthlyLimit = limits.MonthlyRequests
	quota.OverageAllowed = limits.OverageAllowed
	return nil
}
