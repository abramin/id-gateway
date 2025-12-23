package requestlimit

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"credo/internal/ratelimit/config"
	"credo/internal/ratelimit/models"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	request "credo/pkg/platform/middleware/request"
	"credo/pkg/platform/privacy"
)

const keyPrefixUser = "user"
const keyPrefixIP = "ip"

type BucketStore interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (*models.RateLimitResult, error)
	AllowN(ctx context.Context, key string, cost, limit int, window time.Duration) (*models.RateLimitResult, error)
}

type AllowlistStore interface {
	IsAllowlisted(ctx context.Context, identifier string) (bool, error)
}

type AuditPublisher interface {
	Emit(ctx context.Context, event audit.Event) error
}

type Service struct {
	buckets        BucketStore
	allowlist      AllowlistStore
	auditPublisher AuditPublisher
	logger         *slog.Logger
	config         *config.Config
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

func WithConfig(cfg *config.Config) Option {
	return func(s *Service) {
		s.config = cfg
	}
}

func New(
	buckets BucketStore,
	allowlist AllowlistStore,
	opts ...Option,
) (*Service, error) {
	if buckets == nil {
		return nil, fmt.Errorf("buckets store is required")
	}
	if allowlist == nil {
		return nil, fmt.Errorf("allowlist store is required")
	}

	svc := &Service{
		buckets:   buckets,
		allowlist: allowlist,
		config:    config.DefaultConfig(),
	}

	for _, opt := range opts {
		opt(svc)
	}

	return svc, nil
}

func (s *Service) CheckIP(ctx context.Context, ip string, class models.EndpointClass) (*models.RateLimitResult, error) {
	requestsPerWindow, window := s.config.GetIPLimit(class)
	return s.checkRateLimit(ctx, ip, class, keyPrefixIP, requestsPerWindow, window, privacy.AnonymizeIP(ip))
}

func (s *Service) CheckUser(ctx context.Context, userID string, class models.EndpointClass) (*models.RateLimitResult, error) {
	requestsPerWindow, window := s.config.GetUserLimit(class)
	return s.checkRateLimit(ctx, userID, class, keyPrefixUser, requestsPerWindow, window, userID)
}

func (s *Service) checkRateLimit(
	ctx context.Context,
	identifier string,
	class models.EndpointClass,
	keyPrefix string,
	requestsPerWindow int,
	window time.Duration,
	logIdentifier string,
) (*models.RateLimitResult, error) {
	a, err := s.allowlist.IsAllowlisted(ctx, identifier)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to check allowlist")
	}
	if a {
		return &models.RateLimitResult{
			Allowed:    true,
			Limit:      requestsPerWindow,
			Remaining:  requestsPerWindow,
			ResetAt:    time.Now().Add(window),
			RetryAfter: 0,
		}, nil
	}

	key := fmt.Sprintf("%s:%s:%s", keyPrefix, identifier, class)
	result, err := s.buckets.Allow(ctx, key, requestsPerWindow, window)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to check rate limit")
	}

	if !result.Allowed {
		s.logAudit(ctx, keyPrefix+"_rate_limit_exceeded",
			"identifier", logIdentifier,
			"endpoint_class", class,
			"limit", requestsPerWindow,
			"window_seconds", int(window.Seconds()),
		)
	}

	return result, nil
}

func (s *Service) CheckBoth(ctx context.Context, ip, userID string, class models.EndpointClass) (*models.RateLimitResult, error) {
	requestsPerWindow, window := s.config.GetIPLimit(class)
	ipRes, err := s.checkRateLimit(ctx, ip, class, keyPrefixIP, requestsPerWindow, window, privacy.AnonymizeIP(ip))
	if err != nil {
		return nil, err
	}
	if !ipRes.Allowed {
		return ipRes, nil
	}
	requestsPerWindow, window = s.config.GetUserLimit(class)
	userRes, err := s.checkRateLimit(ctx, userID, class, keyPrefixUser, requestsPerWindow, window, userID)
	if err != nil {
		return nil, err
	}
	if !userRes.Allowed {
		return userRes, nil
	}

	// If both pass, return a combined result that shows the more restrictive remaining count and reset time
	if ipRes.Remaining < userRes.Remaining {
		return ipRes, nil
	} else if userRes.Remaining < ipRes.Remaining {
		return userRes, nil
	} else {
		// If remaining counts are equal, return the one with the earlier reset time
		if ipRes.ResetAt.Before(userRes.ResetAt) {
			return ipRes, nil
		} else {
			return userRes, nil
		}
	}
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
