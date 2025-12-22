package quota

import (
	"context"
	"time"

	"credo/internal/ratelimit/models"
	id "credo/pkg/domain"
)

type InMemoryQuotaStore struct {
	quotas map[id.APIKeyID]*models.APIKeyQuota
}

func New() *InMemoryQuotaStore {
	return &InMemoryQuotaStore{
		quotas: make(map[id.APIKeyID]*models.APIKeyQuota),
	}
}

func (s *InMemoryQuotaStore) GetQuota(_ context.Context, apiKeyID id.APIKeyID) (*models.APIKeyQuota, error) {
	if quota, exists := s.quotas[apiKeyID]; exists {
		return quota, nil
	}
	return nil, nil
}

func (s *InMemoryQuotaStore) IncrementUsage(_ context.Context, apiKeyID id.APIKeyID, count int) (*models.APIKeyQuota, error) {
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
