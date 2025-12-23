package quota

import (
	"context"
	"time"

	c "credo/internal/ratelimit/config"
	"credo/internal/ratelimit/models"
	id "credo/pkg/domain"
)

type InMemoryQuotaStore struct {
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
	if quota, exists := s.quotas[apiKeyID]; exists {
		return quota, nil
	}
	return nil, nil
}

func (s *InMemoryQuotaStore) IncrementUsage(_ context.Context, apiKeyID id.APIKeyID, count int) (quota *models.APIKeyQuota, err error) {
	quota, exists := s.quotas[apiKeyID]
	if !exists {
		limits := s.config.QuotaTiers[models.QuotaTierFree]
		quota = &models.APIKeyQuota{
			APIKeyID:       apiKeyID,
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
