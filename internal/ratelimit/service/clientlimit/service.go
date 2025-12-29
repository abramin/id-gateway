// Package clientlimit implements per-OAuth-client rate limiting (PRD-017 FR-2c).
package clientlimit

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"credo/internal/ratelimit/config"
	"credo/internal/ratelimit/models"
	"credo/internal/ratelimit/observability"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/middleware/requesttime"
)

type BucketStore interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (*models.RateLimitResult, error)
}

// ClientLookup provides OAuth client type information.
type ClientLookup interface {
	IsConfidentialClient(ctx context.Context, clientID string) (bool, error)
}

type Service struct {
	buckets        BucketStore
	clientLookup   ClientLookup
	auditPublisher observability.AuditPublisher
	logger         *slog.Logger
	config         *config.ClientLimitConfig
}

type Option func(*Service)

func WithLogger(logger *slog.Logger) Option {
	return func(s *Service) {
		s.logger = logger
	}
}

func WithAuditPublisher(publisher observability.AuditPublisher) Option {
	return func(s *Service) {
		s.auditPublisher = publisher
	}
}

func WithConfig(cfg *config.ClientLimitConfig) Option {
	return func(s *Service) {
		s.config = cfg
	}
}

func New(buckets BucketStore, clientLookup ClientLookup, opts ...Option) (*Service, error) {
	if buckets == nil {
		return nil, fmt.Errorf("buckets store is required")
	}
	if clientLookup == nil {
		return nil, fmt.Errorf("client lookup is required")
	}

	defaultCfg := config.DefaultConfig().ClientLimits
	svc := &Service{
		buckets:      buckets,
		clientLookup: clientLookup,
		config:       &defaultCfg,
	}

	for _, opt := range opts {
		opt(svc)
	}

	return svc, nil
}

func (s *Service) Check(ctx context.Context, clientID, endpoint string) (*models.RateLimitResult, error) {
	if clientID == "" {
		return &models.RateLimitResult{
			Allowed:   true,
			Limit:     0,
			Remaining: 0,
			ResetAt:   requesttime.Now(ctx),
		}, nil
	}

	isConfidential, err := s.clientLookup.IsConfidentialClient(ctx, clientID)
	if err != nil {
		// Log error but don't fail the request - default to public client limits
		if s.logger != nil {
			s.logger.Warn("failed to lookup client type, using public limits",
				"client_id", anonymizeClientID(clientID),
				"error", err,
			)
		}
		isConfidential = false
	}

	var limit config.Limit
	var clientType string
	if isConfidential {
		limit = s.config.ConfidentialLimit
		clientType = "confidential"
	} else {
		limit = s.config.PublicLimit
		clientType = "public"
	}

	key := models.NewClientRateLimitKey(clientID, endpoint)

	result, err := s.buckets.Allow(ctx, key, limit.RequestsPerWindow, limit.Window)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to check client rate limit")
	}

	if !result.Allowed {
		observability.LogAudit(ctx, s.logger, s.auditPublisher, "client_rate_limit_exceeded",
			"client_id", anonymizeClientID(clientID),
			"client_type", clientType,
			"endpoint", endpoint,
			"limit", limit.RequestsPerWindow,
			"window_seconds", int(limit.Window.Seconds()),
		)
	}

	return result, nil
}

func anonymizeClientID(clientID string) string {
	if len(clientID) <= 8 {
		return clientID[:len(clientID)/2] + "***"
	}
	return clientID[:4] + "***" + clientID[len(clientID)-4:]
}
