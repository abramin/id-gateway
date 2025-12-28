// Package quota manages monthly API key usage limits for partner integrations.
//
// Partner API keys have tiered monthly quotas (Free, Starter, Business, Enterprise).
// Quotas reset on the first day of each calendar month.
//
// Usage:
//
//	svc, _ := quota.New(store)
//	quota, _ := svc.Check(ctx, apiKeyID)
//	if quota.IsOverQuota() && !quota.OverageAllowed {
//	    // Return 429 Quota Exceeded
//	}
//	svc.Increment(ctx, apiKeyID, 1)  // Track usage
package quota

import (
	"context"
	"fmt"
	"log/slog"

	"credo/internal/ratelimit/models"
	"credo/internal/ratelimit/observability"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
)

// Store manages API key usage quotas.
type Store interface {
	GetQuota(ctx context.Context, apiKeyID id.APIKeyID) (*models.APIKeyQuota, error)
	IncrementUsage(ctx context.Context, apiKeyID id.APIKeyID, count int) (*models.APIKeyQuota, error)
	ResetQuota(ctx context.Context, apiKeyID id.APIKeyID) error
	ListQuotas(ctx context.Context) ([]*models.APIKeyQuota, error)
	UpdateTier(ctx context.Context, apiKeyID id.APIKeyID, tier models.QuotaTier) error
}

// Service manages API key quota tracking and enforcement.
type Service struct {
	store          Store
	auditPublisher observability.AuditPublisher
	logger         *slog.Logger
}

// Option configures a Service instance.
type Option func(*Service)

// WithLogger sets the structured logger for audit and debug logging.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Service) {
		s.logger = logger
	}
}

// WithAuditPublisher sets the audit event publisher for security logging.
func WithAuditPublisher(publisher observability.AuditPublisher) Option {
	return func(s *Service) {
		s.auditPublisher = publisher
	}
}

// New creates a quota service with the given store and options.
func New(store Store, opts ...Option) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("quota store is required")
	}

	svc := &Service{
		store: store,
	}

	for _, opt := range opts {
		opt(svc)
	}

	return svc, nil
}

// Check retrieves the current quota for an API key.
// Returns CodeNotFound if the API key has no quota record.
func (s *Service) Check(ctx context.Context, apiKeyID id.APIKeyID) (*models.APIKeyQuota, error) {
	quota, err := s.store.GetQuota(ctx, apiKeyID)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to get API key quota")
	}
	if quota == nil {
		return nil, dErrors.Wrap(fmt.Errorf("quota not found for API key %s", apiKeyID), dErrors.CodeNotFound, "quota not found")
	}
	return quota, nil
}

// Increment adds to the usage counter for an API key.
// Emits an audit event when quota is exceeded (for billing/monitoring).
func (s *Service) Increment(ctx context.Context, apiKeyID id.APIKeyID, count int) (*models.APIKeyQuota, error) {
	quota, err := s.store.IncrementUsage(ctx, apiKeyID, count)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to increment API key usage")
	}

	// Log if quota exceeded
	if quota != nil && quota.CurrentUsage > quota.MonthlyLimit && quota.MonthlyLimit > 0 {
		observability.LogAudit(ctx, s.logger, s.auditPublisher, "api_key_quota_exceeded",
			"api_key_id", apiKeyID,
			"current_usage", quota.CurrentUsage,
			"monthly_limit", quota.MonthlyLimit,
		)
	}

	return quota, nil
}

// Reset clears the usage counter for an API key (admin operation).
// Typically used for customer service or billing adjustments.
func (s *Service) Reset(ctx context.Context, apiKeyID id.APIKeyID) error {
	if apiKeyID.IsNil() {
		return dErrors.New(dErrors.CodeBadRequest, "api_key_id is required")
	}

	if err := s.store.ResetQuota(ctx, apiKeyID); err != nil {
		return dErrors.Wrap(err, dErrors.CodeInternal, "failed to reset quota")
	}

	observability.LogAudit(ctx, s.logger, s.auditPublisher, "api_key_quota_reset",
		"api_key_id", apiKeyID,
	)

	return nil
}

// List returns all quota records for admin dashboard display.
func (s *Service) List(ctx context.Context) ([]*models.APIKeyQuota, error) {
	quotas, err := s.store.ListQuotas(ctx)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to list quotas")
	}
	return quotas, nil
}

// UpdateTier changes the subscription tier for an API key.
// Takes effect immediately; does not reset current usage.
func (s *Service) UpdateTier(ctx context.Context, apiKeyID id.APIKeyID, tier models.QuotaTier) error {
	if apiKeyID.IsNil() {
		return dErrors.New(dErrors.CodeBadRequest, "api_key_id is required")
	}
	if !tier.IsValid() {
		return dErrors.New(dErrors.CodeBadRequest, "invalid tier")
	}

	if err := s.store.UpdateTier(ctx, apiKeyID, tier); err != nil {
		return dErrors.Wrap(err, dErrors.CodeInternal, "failed to update tier")
	}

	observability.LogAudit(ctx, s.logger, s.auditPublisher, "api_key_tier_updated",
		"api_key_id", apiKeyID,
		"tier", tier,
	)

	return nil
}
