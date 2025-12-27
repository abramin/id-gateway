// Package requestlimit provides per-IP and per-user rate limiting.
//
// This is the primary rate limiting service used by middleware to enforce
// request quotas on API endpoints. It implements sliding window rate limiting
// with configurable limits per endpoint class.
//
// Usage:
//
//	svc, _ := requestlimit.New(bucketStore, allowlistStore)
//	result, _ := svc.CheckIP(ctx, clientIP, models.ClassAuth)
//	if !result.Allowed {
//	    // Return 429 Too Many Requests
//	}
//
// The service checks allowlist entries before applying rate limits,
// allowing admins to exempt specific IPs or users from limiting.
package requestlimit

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"credo/internal/ratelimit/config"
	"credo/internal/ratelimit/metrics"
	"credo/internal/ratelimit/models"
	"credo/internal/ratelimit/observability"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	requesttime "credo/pkg/platform/middleware/requesttime"
	"credo/pkg/platform/privacy"
)

// BucketStore checks rate limits using sliding window counters.
type BucketStore interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (*models.RateLimitResult, error)
}

// AllowlistStore checks if an identifier should bypass rate limiting.
type AllowlistStore interface {
	IsAllowlisted(ctx context.Context, identifier string) (bool, error)
}

// AuditPublisher emits audit events for security-relevant operations.
type AuditPublisher interface {
	Emit(ctx context.Context, event audit.Event) error
}

// Service enforces per-IP and per-user rate limits using sliding window counters.
// Thread-safe for concurrent use by HTTP middleware.
type Service struct {
	buckets        BucketStore
	allowlist      AllowlistStore
	auditPublisher AuditPublisher
	logger         *slog.Logger
	config         *config.Config
	metrics        *metrics.Metrics
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
func WithAuditPublisher(publisher AuditPublisher) Option {
	return func(s *Service) {
		s.auditPublisher = publisher
	}
}

// WithConfig overrides the default rate limit configuration.
func WithConfig(cfg *config.Config) Option {
	return func(s *Service) {
		s.config = cfg
	}
}

// WithMetrics sets the metrics recorder for observability.
func WithMetrics(m *metrics.Metrics) Option {
	return func(s *Service) {
		s.metrics = m
	}
}

// New creates a rate limiting service with the given stores and options.
// Returns an error if required stores are nil.
func New(
	buckets BucketStore,
	allowlist AllowlistStore,
	opts ...Option,
) (*Service, error) {
	if buckets == nil {
		return nil, errors.New("buckets store is required")
	}
	if allowlist == nil {
		return nil, errors.New("allowlist store is required")
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

// CheckIP enforces per-IP rate limits for unauthenticated requests.
// Used by middleware.RateLimit for endpoints that don't require authentication.
// Returns Allowed=false if the IP has exceeded its quota for the endpoint class.
func (s *Service) CheckIP(ctx context.Context, ip string, class models.EndpointClass) (*models.RateLimitResult, error) {
	requestsPerWindow, window, ok := s.config.GetIPLimit(class)
	if !ok {
		// Default-deny: no limit configured for this class (PRD-017 FR-1)
		observability.LogAudit(ctx, s.logger, s.auditPublisher, "rate_limit_config_missing",
			"identifier", privacy.AnonymizeIP(ip),
			"endpoint_class", class,
			"limit_type", models.KeyPrefixIP,
		)
		return &models.RateLimitResult{
			Allowed:    false,
			Limit:      0,
			Remaining:  0,
			ResetAt:    requesttime.Now(ctx),
			RetryAfter: 60, // Retry in 60 seconds
		}, nil
	}
	return s.checkRateLimit(ctx, ip, class, models.KeyPrefixIP, requestsPerWindow, window, privacy.AnonymizeIP(ip))
}

// CheckUser enforces per-user rate limits.
// Used when you want to limit by user identity only, ignoring IP.
// Returns Allowed=false if the user has exceeded their quota for the endpoint class.
func (s *Service) CheckUser(ctx context.Context, userID string, class models.EndpointClass) (*models.RateLimitResult, error) {
	requestsPerWindow, window, ok := s.config.GetUserLimit(class)
	if !ok {
		// Default-deny: no limit configured for this class (PRD-017 FR-1)
		observability.LogAudit(ctx, s.logger, s.auditPublisher, "rate_limit_config_missing",
			"identifier", userID,
			"endpoint_class", class,
			"limit_type", models.KeyPrefixUser,
		)
		return &models.RateLimitResult{
			Allowed:    false,
			Limit:      0,
			Remaining:  0,
			ResetAt:    requesttime.Now(ctx),
			RetryAfter: 60, // Retry in 60 seconds
		}, nil
	}
	return s.checkRateLimit(ctx, userID, class, models.KeyPrefixUser, requestsPerWindow, window, userID)
}

// limitParams groups parameters for a single rate limit check.
type limitParams struct {
	identifier    string
	logIdentifier string
	prefix        models.KeyPrefix
	limit         int
	window        time.Duration
}

func (s *Service) checkRateLimit(
	ctx context.Context,
	identifier string,
	class models.EndpointClass,
	keyPrefix models.KeyPrefix,
	requestsPerWindow int,
	window time.Duration,
	logIdentifier string,
) (*models.RateLimitResult, error) {
	now := requesttime.Now(ctx)

	a, err := s.allowlist.IsAllowlisted(ctx, identifier)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to check allowlist")
	}
	if a {
		// Record allowlist bypass metrics and audit
		bypassType := string(keyPrefix)
		if s.metrics != nil {
			s.metrics.RecordAllowlistBypass(bypassType)
		}
		observability.LogAudit(ctx, s.logger, s.auditPublisher, "allowlist_bypass",
			"identifier", logIdentifier,
			"endpoint_class", class,
			"bypass_type", bypassType,
		)
		return &models.RateLimitResult{
			Allowed:    true,
			Bypassed:   true,
			Limit:      requestsPerWindow,
			Remaining:  requestsPerWindow,
			ResetAt:    now.Add(window),
			RetryAfter: 0,
		}, nil
	}

	key := models.NewRateLimitKey(keyPrefix, identifier, class)
	result, err := s.buckets.Allow(ctx, key.String(), requestsPerWindow, window)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to check rate limit")
	}

	if !result.Allowed {
		observability.LogAudit(ctx, s.logger, s.auditPublisher, string(keyPrefix)+"_rate_limit_exceeded",
			"identifier", logIdentifier,
			"endpoint_class", class,
			"limit", requestsPerWindow,
			"window_seconds", int(window.Seconds()),
		)
	}

	return result, nil
}

// checkSingleLimit performs a rate limit check without allowlist handling.
// Used by CheckBoth after allowlist checks are done upfront.
func (s *Service) checkSingleLimit(ctx context.Context, p limitParams, class models.EndpointClass) (*models.RateLimitResult, error) {
	key := models.NewRateLimitKey(p.prefix, p.identifier, class)
	res, err := s.buckets.Allow(ctx, key.String(), p.limit, p.window)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to check "+string(p.prefix)+" rate limit")
	}
	if !res.Allowed {
		observability.LogAudit(ctx, s.logger, s.auditPublisher, string(p.prefix)+"_rate_limit_exceeded",
			"identifier", p.logIdentifier,
			"endpoint_class", class,
			"limit", p.limit,
			"window_seconds", int(p.window.Seconds()),
		)
	}
	return res, nil
}

// CheckBoth enforces both IP and user rate limits for authenticated requests.
// Used by middleware.RateLimitAuthenticated for protected endpoints.
//
// Behavior:
//   - Checks allowlist first; if either IP or user is allowlisted, request is bypassed
//   - Applies IP limit first; if exceeded, returns immediately (fail fast)
//   - Applies user limit second
//   - Returns the more restrictive result (lower remaining count wins)
//
// This is the primary entry point for authenticated request rate limiting.
func (s *Service) CheckBoth(ctx context.Context, ip, userID string, class models.EndpointClass) (*models.RateLimitResult, error) {
	now := requesttime.Now(ctx)

	// Get limits upfront to fail fast if config is missing
	ipLimit, userLimit, denial := s.getBothLimits(ctx, ip, userID, class, now)
	if denial != nil {
		return denial, nil
	}

	// Check allowlist for both identifiers upfront
	bypassed, result := s.checkAllowlistBypass(ctx, ip, userID, class, ipLimit, userLimit, now)
	if bypassed {
		return result, nil
	}

	// Check IP rate limit first (early return if denied)
	ipRes, err := s.checkSingleLimit(ctx, *ipLimit, class)
	if err != nil {
		return nil, err
	}
	if !ipRes.Allowed {
		return ipRes, nil
	}

	// Check user rate limit
	userRes, err := s.checkSingleLimit(ctx, *userLimit, class)
	if err != nil {
		return nil, err
	}
	if !userRes.Allowed {
		return userRes, nil
	}

	return moreRestrictiveResult(ipRes, userRes), nil
}

// getBothLimits retrieves IP and user limits, returning a denial result if config is missing.
func (s *Service) getBothLimits(ctx context.Context, ip, userID string, class models.EndpointClass, now time.Time) (*limitParams, *limitParams, *models.RateLimitResult) {
	denial := &models.RateLimitResult{
		Allowed:    false,
		Limit:      0,
		Remaining:  0,
		ResetAt:    now,
		RetryAfter: 60,
	}

	ipRequestsPerWindow, ipWindow, ipOk := s.config.GetIPLimit(class)
	if !ipOk {
		observability.LogAudit(ctx, s.logger, s.auditPublisher, "rate_limit_config_missing",
			"identifier", privacy.AnonymizeIP(ip),
			"endpoint_class", class,
			"limit_type", models.KeyPrefixIP,
		)
		return nil, nil, denial
	}

	userRequestsPerWindow, userWindow, userOk := s.config.GetUserLimit(class)
	if !userOk {
		observability.LogAudit(ctx, s.logger, s.auditPublisher, "rate_limit_config_missing",
			"identifier", userID,
			"endpoint_class", class,
			"limit_type", models.KeyPrefixUser,
		)
		return nil, nil, denial
	}

	ipParams := &limitParams{
		identifier:    ip,
		logIdentifier: privacy.AnonymizeIP(ip),
		prefix:        models.KeyPrefixIP,
		limit:         ipRequestsPerWindow,
		window:        ipWindow,
	}
	userParams := &limitParams{
		identifier:    userID,
		logIdentifier: userID,
		prefix:        models.KeyPrefixUser,
		limit:         userRequestsPerWindow,
		window:        userWindow,
	}
	return ipParams, userParams, nil
}

// checkAllowlistBypass checks if either IP or user is allowlisted and returns bypass result.
func (s *Service) checkAllowlistBypass(ctx context.Context, ip, userID string, class models.EndpointClass, ipLimit, userLimit *limitParams, now time.Time) (bool, *models.RateLimitResult) {
	ipAllowlisted, err := s.allowlist.IsAllowlisted(ctx, ip)
	if err != nil {
		return false, nil
	}
	userAllowlisted, err := s.allowlist.IsAllowlisted(ctx, userID)
	if err != nil {
		return false, nil
	}

	if !ipAllowlisted && !userAllowlisted {
		return false, nil
	}

	bypassType := "ip"
	if userAllowlisted {
		bypassType = "user"
	}
	if s.metrics != nil {
		s.metrics.RecordAllowlistBypass(bypassType)
	}
	observability.LogAudit(ctx, s.logger, s.auditPublisher, "allowlist_bypass",
		"ip", privacy.AnonymizeIP(ip),
		"user_id", userID,
		"endpoint_class", class,
		"bypass_type", bypassType,
	)

	// Return the more restrictive limit info for consistency
	limit, window := ipLimit.limit, ipLimit.window
	if userLimit.limit < ipLimit.limit {
		limit, window = userLimit.limit, userLimit.window
	}
	return true, &models.RateLimitResult{
		Allowed:    true,
		Bypassed:   true,
		Limit:      limit,
		Remaining:  limit,
		ResetAt:    now.Add(window),
		RetryAfter: 0,
	}
}

// moreRestrictiveResult returns the result with fewer remaining requests,
// or the earlier reset time if remaining counts are equal.
func moreRestrictiveResult(a, b *models.RateLimitResult) *models.RateLimitResult {
	if a.Remaining < b.Remaining {
		return a
	}
	if b.Remaining < a.Remaining {
		return b
	}
	if a.ResetAt.Before(b.ResetAt) {
		return a
	}
	return b
}
