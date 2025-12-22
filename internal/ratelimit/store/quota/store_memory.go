package quota

import (
	"context"
	"time"

	"credo/internal/ratelimit/models"
)

type InMemoryQuotaStore struct {
	quotas map[string]*models.APIKeyQuota // keyed by API key ID
}

func New() *InMemoryQuotaStore {
	return &InMemoryQuotaStore{
		quotas: make(map[string]*models.APIKeyQuota),
	}
}

func (s *InMemoryQuotaStore) GetQuota(_ context.Context, apiKeyID string) (*models.APIKeyQuota, error) {
	if quota, exists := s.quotas[apiKeyID]; exists {
		return quota, nil
	}
	return nil, nil
}

func (s *InMemoryQuotaStore) IncrementUsage(_ context.Context, apiKeyID string, count int) (*models.APIKeyQuota, error) {
	quota, exists := s.quotas[apiKeyID]
	if !exists {
		quota = &models.APIKeyQuota{
			APIKeyID:       apiKeyID,
			MonthlyLimit:   1000000, // default limit for new keys
			CurrentUsage:   0,
			OverageAllowed: false,
			PeriodStart:    time.Now(),
			PeriodEnd:      time.Now().AddDate(0, 1, 0),
		}
		s.quotas[apiKeyID] = quota
	}
	quota.CurrentUsage += count
	return quota, nil
}
