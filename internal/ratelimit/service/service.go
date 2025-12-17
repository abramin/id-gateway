package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"credo/internal/audit"
	"credo/internal/platform/middleware"
	"credo/internal/ratelimit/models"
	dErrors "credo/pkg/domain-errors"
)

// Service provides rate limiting and abuse prevention operations.
// Per PRD-017: Core rate limiting service.
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

// Option is a functional option for configuring the Service.
type Option func(*Service)

// WithLogger sets the logger for the service.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Service) {
		s.logger = logger
	}
}

// WithAuditPublisher sets the audit publisher for the service.
func WithAuditPublisher(publisher AuditPublisher) Option {
	return func(s *Service) {
		s.auditPublisher = publisher
	}
}

// WithConfig sets the rate limit configuration.
func WithConfig(cfg *Config) Option {
	return func(s *Service) {
		s.config = cfg
	}
}

// New creates a new rate limiting Service.
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

// SetAuthLockoutStore sets the auth lockout store (optional dependency).
func (s *Service) SetAuthLockoutStore(store AuthLockoutStore) {
	s.authLockout = store
}

// SetQuotaStore sets the quota store (optional dependency).
func (s *Service) SetQuotaStore(store QuotaStore) {
	s.quotas = store
}

// SetGlobalThrottleStore sets the global throttle store (optional dependency).
func (s *Service) SetGlobalThrottleStore(store GlobalThrottleStore) {
	s.globalThrottle = store
}

// CheckIPRateLimit checks the per-IP rate limit for an endpoint class.
// Per PRD-017 FR-1: Per-IP rate limiting.
//
// TODO: Implement this method
// 1. Check if IP is allowlisted - if so, return allowed with max limits
// 2. Build rate limit key: "ip:{ip}:{class}"
// 3. Get limit and window for endpoint class from config
// 4. Call buckets.Allow() to check and increment
// 5. If not allowed, emit audit event "rate_limit_exceeded"
// 6. Return RateLimitResult with headers info
func (s *Service) CheckIPRateLimit(ctx context.Context, ip string, class models.EndpointClass) (*models.RateLimitResult, error) {
	// TODO: Implement - see steps above
	return nil, dErrors.New(dErrors.CodeInternal, "not implemented")
}

// CheckUserRateLimit checks the per-user rate limit for an endpoint class.
// Per PRD-017 FR-2: Per-user rate limiting.
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
// Per PRD-017 FR-2: Both must pass for authenticated endpoints.
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
// Per PRD-017 FR-2b: OWASP authentication-specific protections.
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
// Per PRD-017 FR-2b: Track failures for lockout.
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
// Per PRD-017 FR-2b: Clear state on success.
//
// TODO: Implement this method
func (s *Service) ClearAuthFailures(ctx context.Context, identifier, ip string) error {
	// TODO: Implement
	return dErrors.New(dErrors.CodeInternal, "not implemented")
}

// GetProgressiveBackoff calculates backoff delay based on failure count.
// Per PRD-017 FR-2b: Progressive backoff (250ms → 500ms → 1s).
//
// TODO: Implement this method
// Returns delay duration based on failure count
func (s *Service) GetProgressiveBackoff(failureCount int) time.Duration {
	// TODO: Implement progressive backoff calculation
	// Base: 250ms, doubles each failure, max 1s
	return 0
}

// CheckAPIKeyQuota checks quota for partner API key.
// Per PRD-017 FR-5: Partner API quotas.
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
// Per PRD-017 FR-6: Global throttling.
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
// Per PRD-017 FR-4: Admin allowlist management.
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
// Per PRD-017 FR-4: Admin allowlist management.
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
// Per PRD-017 FR-4: Admin can view allowlist.
//
// TODO: Implement this method
func (s *Service) ListAllowlist(ctx context.Context) ([]*models.AllowlistEntry, error) {
	// TODO: Implement
	return nil, dErrors.New(dErrors.CodeInternal, "not implemented")
}

// ResetRateLimit resets the rate limit counter for an identifier.
// Per PRD-017 TR-1: Admin reset operation.
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
