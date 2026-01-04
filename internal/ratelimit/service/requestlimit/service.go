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
	"credo/pkg/platform/privacy"
	"credo/pkg/requestcontext"
)

// BucketStore checks rate limits using sliding window counters.
type BucketStore interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (*models.RateLimitResult, error)
}

// AllowlistStore checks if an identifier should bypass rate limiting.
type AllowlistStore interface {
	IsAllowlisted(ctx context.Context, identifier string) (bool, error)
}

// Service enforces per-IP and per-user rate limits using sliding window counters.
// Thread-safe for concurrent use by HTTP middleware.
type Service struct {
	buckets        BucketStore
	allowlist      AllowlistStore
	auditPublisher observability.AuditPublisher
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
func WithAuditPublisher(publisher observability.AuditPublisher) Option {
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
			ResetAt:    requestcontext.Now(ctx),
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
			ResetAt:    requestcontext.Now(ctx),
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
	now := requestcontext.Now(ctx)

	// Check allowlist (result used later, not for early return)
	allowlisted, allowlistErr := s.allowlist.IsAllowlisted(ctx, identifier)
	if allowlistErr != nil {
		return nil, dErrors.Wrap(allowlistErr, dErrors.CodeInternal, "failed to check allowlist")
	}

	// SECURITY: Always perform bucket check regardless of allowlist status.
	// This ensures constant-time behavior to prevent timing-based enumeration
	// of allowlisted IPs/users. An attacker cannot distinguish allowlisted
	// from non-allowlisted identifiers based on response time.
	key := models.NewRateLimitKey(keyPrefix, identifier, class)
	result, err := s.buckets.Allow(ctx, key.String(), requestsPerWindow, window)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to check rate limit")
	}

	// If allowlisted, bypass the rate limit result
	if allowlisted {
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
//   - Gets limits upfront and fails fast if config is missing
//   - Always performs both bucket checks for constant-time behavior (security)
//   - Checks allowlist; if either IP or user is allowlisted, returns bypass result
//   - Otherwise returns the more restrictive result (lower remaining count wins)
//
// This is the primary entry point for authenticated request rate limiting.
func (s *Service) CheckBoth(ctx context.Context, ip, userID string, class models.EndpointClass) (*models.RateLimitResult, error) {
	now := requestcontext.Now(ctx)

	// Get limits upfront to fail fast if config is missing
	ipLimit, userLimit, denial := s.getBothLimits(ctx, ip, userID, class, now)
	if denial != nil {
		return denial, nil
	}

	// Check allowlist for both identifiers (results used later, not for early return)
	ipAllowlisted, userAllowlisted := s.checkAllowlistStatus(ctx, ip, userID)

	// SECURITY: Always perform both bucket checks regardless of allowlist status.
	// This ensures constant-time behavior to prevent timing-based enumeration
	// of allowlisted IPs/users.
	ipRes, err := s.checkSingleLimit(ctx, *ipLimit, class)
	if err != nil {
		return nil, err
	}

	userRes, err := s.checkSingleLimit(ctx, *userLimit, class)
	if err != nil {
		return nil, err
	}

	// If either is allowlisted, return bypass result
	if ipAllowlisted || userAllowlisted {
		return s.buildBypassResult(ctx, ip, userID, class, ipLimit, userLimit, now, ipAllowlisted, userAllowlisted), nil
	}

	// Both denied → return IP denial (checked first)
	if !ipRes.Allowed {
		return ipRes, nil
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

// checkAllowlistStatus checks if IP or user is allowlisted.
// Errors are swallowed and treated as not-allowlisted to maintain constant-time behavior.
func (s *Service) checkAllowlistStatus(ctx context.Context, ip, userID string) (ipAllowlisted, userAllowlisted bool) {
	ipAllowlisted, _ = s.allowlist.IsAllowlisted(ctx, ip)     //nolint:errcheck // errors treated as not-allowlisted
	userAllowlisted, _ = s.allowlist.IsAllowlisted(ctx, userID) //nolint:errcheck // errors treated as not-allowlisted
	return ipAllowlisted, userAllowlisted
}

// buildBypassResult constructs the bypass result for allowlisted requests.
// Records audit log and metrics.
// Returns the more restrictive limit info for consistency.
// Used when either IP or user is allowlisted.
// Bypass type is "ip" if IP is allowlisted, else "user".
func (s *Service) buildBypassResult(ctx context.Context, ip, userID string, class models.EndpointClass, ipLimit, userLimit *limitParams, now time.Time, ipAllowlisted, userAllowlisted bool) *models.RateLimitResult {
	bypassType := "ip"
	if !ipAllowlisted && userAllowlisted {
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
	return &models.RateLimitResult{
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
