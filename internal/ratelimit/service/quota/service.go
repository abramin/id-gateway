package quota

import (
	"context"
	"fmt"
	"log/slog"

	"credo/internal/ratelimit/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	request "credo/pkg/platform/middleware/request"
)

type Store interface {
	GetQuota(ctx context.Context, apiKeyID id.APIKeyID) (*models.APIKeyQuota, error)
	IncrementUsage(ctx context.Context, apiKeyID id.APIKeyID, count int) (*models.APIKeyQuota, error)
}

type AuditPublisher interface {
	Emit(ctx context.Context, event audit.Event) error
}

type Service struct {
	store          Store
	auditPublisher AuditPublisher
	logger         *slog.Logger
}

type Option func(*Service)

func WithLogger(logger *slog.Logger) Option {
	return func(s *Service) {
		s.logger = logger
	}
}

func WithAuditPublisher(publisher AuditPublisher) Option {
	return func(s *Service) {
		s.auditPublisher = publisher
	}
}

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

func (s *Service) Increment(ctx context.Context, apiKeyID id.APIKeyID, count int) (*models.APIKeyQuota, error) {
	quota, err := s.store.IncrementUsage(ctx, apiKeyID, count)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to increment API key usage")
	}

	// Log if quota exceeded
	if quota != nil && quota.CurrentUsage > quota.MonthlyLimit && quota.MonthlyLimit > 0 {
		s.logAudit(ctx, "api_key_quota_exceeded",
			"api_key_id", apiKeyID,
			"current_usage", quota.CurrentUsage,
			"monthly_limit", quota.MonthlyLimit,
		)
	}

	return quota, nil
}

func (s *Service) logAudit(ctx context.Context, event string, attrs ...any) {
	if requestID := request.GetRequestID(ctx); requestID != "" {
		attrs = append(attrs, "request_id", requestID)
	}
	args := append(attrs, "event", event, "log_type", "audit")
	if s.logger != nil {
		s.logger.InfoContext(ctx, event, args...)
	}
	if s.auditPublisher == nil {
		return
	}
	_ = s.auditPublisher.Emit(ctx, audit.Event{
		Action: event,
	})
}
