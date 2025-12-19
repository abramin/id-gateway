package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"credo/internal/audit"
	"credo/internal/platform/middleware"
	"credo/internal/platform/privacy"
	"credo/internal/ratelimit/models"
	dErrors "credo/pkg/domain-errors"
)

type Service struct {
	buckets        BucketStore
	allowlist      AllowlistStore
	authLockout    AuthLockoutStore
	quotas         QuotaStore
	globalThrottle GlobalThrottleStore
	auditPublisher AuditPublisher
	logger         *slog.Logger
	config         *Config
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

func WithConfig(cfg *Config) Option {
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
		config:    DefaultConfig(),
	}

	for _, opt := range opts {
		opt(svc)
	}

	return svc, nil
}

func (s *Service) SetAuthLockoutStore(store AuthLockoutStore) {
	s.authLockout = store
}

func (s *Service) SetQuotaStore(store QuotaStore) {
	s.quotas = store
}

func (s *Service) SetGlobalThrottleStore(store GlobalThrottleStore) {
	s.globalThrottle = store
}

// CheckIPRateLimit checks the per-IP rate limit for an endpoint class.
func (s *Service) CheckIPRateLimit(ctx context.Context, ip string, class models.EndpointClass) (*models.RateLimitResult, error) {
	a, err := s.allowlist.IsAllowlisted(ctx, ip)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to check allowlist")
	}
	if a {
		return &models.RateLimitResult{
			Allowed:    true,
			Limit:      s.config.Global.GlobalPerSecond,
			Remaining:  s.config.Global.GlobalPerSecond,
			ResetAt:    time.Now().Add(24 * time.Hour),
			RetryAfter: 0,
		}, nil
	}

	requestsPerWindow, window := s.config.GetIPLimit(class)
	key := fmt.Sprintf("ip:%s:%s", ip, class)

	result, err := s.buckets.Allow(ctx, key, requestsPerWindow, window)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to check IP rate limit")
	}

	if !result.Allowed {
		s.logAudit(ctx, "rate_limit_exceeded",
			"identifier", privacy.AnonymizeIP(ip),
			"endpoint_class", class,
			"limit", requestsPerWindow,
			"window_seconds", int(window.Seconds()),
		)
	}

	return result, nil
}

// CheckUserRateLimit checks the per-user rate limit for an endpoint class.
//
// TODO: Implement this method
// 1. Check if userID is allowlisted - if so, return allowed with max limits
// 2. Build rate limit key: "user:{userID}:{class}"
// 3. Get user limit and window for endpoint class from config
// 4. Call buckets.Allow() to check and increment
// 5. If not allowed, emit audit event "user_rate_limit_exceeded"
// 6. Return RateLimitResult with quota info
func (s *Service) CheckUserRateLimit(ctx context.Context, userID string, class models.EndpointClass) (*models.RateLimitResult, error) {
	// TODO: Implement - see steps above
	return nil, dErrors.New(dErrors.CodeInternal, "not implemented")
}

// CheckBothLimits checks both IP and user rate limits.
//
// TODO: Implement this method
// 1. Check IP rate limit
// 2. If IP limit exceeded, return immediately
// 3. Check user rate limit
// 4. Return the more restrictive result
func (s *Service) CheckBothLimits(ctx context.Context, ip, userID string, class models.EndpointClass) (*models.RateLimitResult, error) {
	// TODO: Implement - see steps above
	return nil, dErrors.New(dErrors.CodeInternal, "not implemented")
}

// CheckAuthRateLimit checks authentication-specific rate limits with lockout.
//
// TODO: Implement this method
// 1. Build composite key: "{email/username}:{ip}"
// 2. Check if currently locked out
// 3. If locked, return 429 with lockout info
// 4. Check standard IP rate limit for auth class
// 5. Apply progressive backoff delay if approaching limit
// 6. Return result with lockout state
func (s *Service) CheckAuthRateLimit(ctx context.Context, identifier, ip string) (*models.RateLimitResult, error) {
	// TODO: Implement - see steps above
	return nil, dErrors.New(dErrors.CodeInternal, "not implemented")
}

// RecordAuthFailure records a failed authentication attempt.
//
// TODO: Implement this method
// 1. Record failure in authLockout store
// 2. Check if hard lock threshold reached (10 failures/day)
// 3. If threshold reached, set locked_until
// 4. Emit audit event "auth.lockout" if locked
// 5. Check if CAPTCHA should be required
func (s *Service) RecordAuthFailure(ctx context.Context, identifier, ip string) (*models.AuthLockout, error) {
	// TODO: Implement - see steps above
	return nil, dErrors.New(dErrors.CodeInternal, "not implemented")
}

// ClearAuthFailures clears auth failure state after successful login.
//
// TODO: Implement this method
func (s *Service) ClearAuthFailures(ctx context.Context, identifier, ip string) error {
	// TODO: Implement
	return dErrors.New(dErrors.CodeInternal, "not implemented")
}

// GetProgressiveBackoff calculates backoff delay based on failure count.
//
// TODO: Implement this method
// Returns delay duration based on failure count
func (s *Service) GetProgressiveBackoff(failureCount int) time.Duration {
	// TODO: Implement progressive backoff calculation
	// Base: 250ms, doubles each failure, max 1s
	return 0
}

// CheckAPIKeyQuota checks quota for partner API key.
//
// TODO: Implement this method
// 1. Get quota for API key
// 2. Check if under monthly limit
// 3. If over limit and overage not allowed, return 429
// 4. If over limit and overage allowed, record overage
// 5. Increment usage counter
// 6. Return quota info for headers
func (s *Service) CheckAPIKeyQuota(ctx context.Context, apiKeyID string) (*models.APIKeyQuota, error) {
	// TODO: Implement - see steps above
	return nil, dErrors.New(dErrors.CodeInternal, "not implemented")
}

// CheckGlobalThrottle checks global request throttle for DDoS protection.
//
// TODO: Implement this method
// 1. Increment global counter
// 2. Check if exceeds per-instance limit
// 3. Check if exceeds global limit (Redis-backed for distributed)
// 4. If exceeded, return 503 response info
func (s *Service) CheckGlobalThrottle(ctx context.Context) (bool, error) {
	// TODO: Implement - see steps above
	return true, nil // Allow by default until implemented
}

// AddToAllowlist adds an IP or user to the rate limit allowlist.
//
// TODO: Implement this method
// 1. Validate request
// 2. Create AllowlistEntry domain object
// 3. Save to allowlist store
// 4. Emit audit event "rate_limit_allowlist_added"
func (s *Service) AddToAllowlist(ctx context.Context, req *models.AddAllowlistRequest, adminUserID string) (*models.AllowlistEntry, error) {
	// TODO: Implement - see steps above
	return nil, dErrors.New(dErrors.CodeInternal, "not implemented")
}

// RemoveFromAllowlist removes an IP or user from the allowlist.
//
// TODO: Implement this method
// 1. Validate request
// 2. Remove from allowlist store
// 3. Emit audit event "rate_limit_allowlist_removed"
func (s *Service) RemoveFromAllowlist(ctx context.Context, req *models.RemoveAllowlistRequest) error {
	// TODO: Implement
	return dErrors.New(dErrors.CodeInternal, "not implemented")
}

// ListAllowlist returns all active allowlist entries.
//
// TODO: Implement this method
func (s *Service) ListAllowlist(ctx context.Context) ([]*models.AllowlistEntry, error) {
	// TODO: Implement
	return nil, dErrors.New(dErrors.CodeInternal, "not implemented")
}

// ResetRateLimit resets the rate limit counter for an identifier.
//
// TODO: Implement this method
// 1. Validate request
// 2. Build key(s) to reset
// 3. Call buckets.Reset() for each key
// 4. Emit audit event "rate_limit_reset"
func (s *Service) ResetRateLimit(ctx context.Context, req *models.ResetRateLimitRequest) error {
	// TODO: Implement
	return dErrors.New(dErrors.CodeInternal, "not implemented")
}

// logAudit emits an audit event for rate limiting operations.
func (s *Service) logAudit(ctx context.Context, event string, attrs ...any) {
	if requestID := middleware.GetRequestID(ctx); requestID != "" {
		attrs = append(attrs, "request_id", requestID)
	}
	args := append(attrs, "event", event, "log_type", "audit")
	if s.logger != nil {
		s.logger.InfoContext(ctx, event, args...)
	}
	if s.auditPublisher == nil {
		return
	}
	// TODO: Extract user_id from attrs and emit audit event
	_ = s.auditPublisher.Emit(ctx, audit.Event{
		Action: event,
	})
}
