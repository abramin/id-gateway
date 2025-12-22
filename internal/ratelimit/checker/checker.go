package checker

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
const keyPrefixAuth = "auth"

// BucketStore defines the persistence interface for rate limit buckets/counters.
type BucketStore interface {
	// Allow checks if a request is allowed and increments the counter.
	Allow(ctx context.Context, key string, limit int, window time.Duration) (*models.RateLimitResult, error)

	// AllowN checks if a request with custom cost is allowed.
	AllowN(ctx context.Context, key string, cost, limit int, window time.Duration) (*models.RateLimitResult, error)
}

// AllowlistStore defines the read-only interface for checking allowlist membership.
type AllowlistStore interface {
	// IsAllowlisted checks if an identifier is in the allowlist and not expired.
	IsAllowlisted(ctx context.Context, identifier string) (bool, error)
}

// AuthLockoutStore defines the persistence interface for authentication lockouts.
type AuthLockoutStore interface {
	// RecordFailure records a failed authentication attempt.
	RecordFailure(ctx context.Context, identifier string) (*models.AuthLockout, error)

	// Get retrieves the current lockout state for an identifier.
	Get(ctx context.Context, identifier string) (*models.AuthLockout, error)

	// Clear clears the lockout state after successful authentication.
	Clear(ctx context.Context, identifier string) error

	// IsLocked checks if an identifier is currently locked out.
	IsLocked(ctx context.Context, identifier string) (bool, *time.Time, error)
}

// QuotaStore defines the persistence interface for partner API quotas.
type QuotaStore interface {
	// GetQuota retrieves the quota for an API key.
	GetQuota(ctx context.Context, apiKeyID string) (*models.APIKeyQuota, error)

	// IncrementUsage increments the usage counter for an API key.
	IncrementUsage(ctx context.Context, apiKeyID string, count int) (*models.APIKeyQuota, error)
}

// GlobalThrottleStore defines the interface for global request throttling.
type GlobalThrottleStore interface {
	// IncrementGlobal increments the global request counter.
	// Returns current count and whether limit is exceeded.
	IncrementGlobal(ctx context.Context) (int, bool, error)

	// GetGlobalCount returns the current global request count.
	GetGlobalCount(ctx context.Context) (int, error)
}

// AuditPublisher defines the interface for publishing audit events.
type AuditPublisher interface {
	Emit(ctx context.Context, event audit.Event) error
}

// Service handles high-traffic rate limit checking operations.
type Service struct {
	buckets        BucketStore
	allowlist      AllowlistStore
	authLockout    AuthLockoutStore
	quotas         QuotaStore
	globalThrottle GlobalThrottleStore
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

func WithQuotaStore(store QuotaStore) Option {
	return func(s *Service) {
		s.quotas = store
	}
}

func WithGlobalThrottleStore(store GlobalThrottleStore) Option {
	return func(s *Service) {
		s.globalThrottle = store
	}
}

func New(
	buckets BucketStore,
	allowlist AllowlistStore,
	authLockout AuthLockoutStore,
	opts ...Option,
) (*Service, error) {
	if buckets == nil {
		return nil, fmt.Errorf("buckets store is required")
	}
	if allowlist == nil {
		return nil, fmt.Errorf("allowlist store is required")
	}
	if authLockout == nil {
		return nil, fmt.Errorf("auth lockout store is required")
	}

	svc := &Service{
		buckets:     buckets,
		allowlist:   allowlist,
		authLockout: authLockout,
		config:      config.DefaultConfig(),
	}

	for _, opt := range opts {
		opt(svc)
	}

	return svc, nil
}

func (s *Service) CheckIPRateLimit(ctx context.Context, ip string, class models.EndpointClass) (*models.RateLimitResult, error) {
	requestsPerWindow, window := s.config.GetIPLimit(class)
	return s.checkRateLimit(ctx, ip, class, keyPrefixIP, requestsPerWindow, window, privacy.AnonymizeIP(ip))
}

func (s *Service) CheckUserRateLimit(ctx context.Context, userID string, class models.EndpointClass) (*models.RateLimitResult, error) {
	requestsPerWindow, window := s.config.GetUserLimit(class)
	return s.checkRateLimit(ctx, userID, class, keyPrefixUser, requestsPerWindow, window, userID)
}

// checkRateLimit is the common rate limiting logic for both IP and user checks.
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

func (s *Service) CheckBothLimits(ctx context.Context, ip, userID string, class models.EndpointClass) (*models.RateLimitResult, error) {
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

func (s *Service) CheckAuthRateLimit(ctx context.Context, identifier, ip string) (*models.AuthRateLimitResult, error) {
	key := fmt.Sprintf("%s:%s:%s", keyPrefixAuth, identifier, ip)
	failureRecord, err := s.authLockout.Get(ctx, key)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to get auth lockout record")
	}

	// Check if currently hard-locked (FR-2b: "hard lock for 15 minutes")
	if failureRecord != nil && failureRecord.LockedUntil != nil && time.Now().Before(*failureRecord.LockedUntil) {
		retryAfter := int(time.Until(*failureRecord.LockedUntil).Seconds())
		s.logAudit(ctx, "auth_lockout_triggered",
			"identifier", identifier,
			"ip", ip,
			"locked_until", failureRecord.LockedUntil,
		)
		return &models.AuthRateLimitResult{
			RateLimitResult: models.RateLimitResult{
				Allowed:    false,
				ResetAt:    *failureRecord.LockedUntil,
				RetryAfter: retryAfter,
			},
			RequiresCaptcha: failureRecord.RequiresCaptcha,
			FailureCount:    failureRecord.FailureCount,
		}, nil
	}

	// Check failure count against sliding window (FR-2b: "5 attempts/15 min")
	if failureRecord != nil && failureRecord.FailureCount >= s.config.AuthLockout.AttemptsPerWindow {
		remaining := s.config.AuthLockout.AttemptsPerWindow - failureRecord.FailureCount
		if remaining <= 0 {
			// Block - too many attempts in window
			resetAt := failureRecord.LastFailureAt.Add(s.config.AuthLockout.WindowDuration)
			return &models.AuthRateLimitResult{
				RateLimitResult: models.RateLimitResult{
					Allowed:    false,
					ResetAt:    resetAt,
					RetryAfter: int(time.Until(resetAt).Seconds()),
				},
				RequiresCaptcha: failureRecord.RequiresCaptcha,
				FailureCount:    failureRecord.FailureCount,
			}, nil
		}
	}

	// Apply progressive backoff (FR-2b: "250ms → 500ms → 1s")
	if failureRecord != nil && failureRecord.FailureCount > 0 {
		delay := s.GetProgressiveBackoff(failureRecord.FailureCount)
		return &models.AuthRateLimitResult{
			RateLimitResult: models.RateLimitResult{
				Allowed:    true,
				Limit:      s.config.AuthLockout.AttemptsPerWindow,
				Remaining:  s.config.AuthLockout.AttemptsPerWindow - failureRecord.FailureCount,
				ResetAt:    time.Now().Add(s.config.AuthLockout.WindowDuration),
				RetryAfter: int(delay.Milliseconds()),
			},
			RequiresCaptcha: failureRecord.RequiresCaptcha,
			FailureCount:    failureRecord.FailureCount,
		}, nil
	}

	// Check standard IP rate limit as secondary defense
	requestsPerWindow, window := s.config.GetIPLimit(models.ClassAuth)
	ipRes, err := s.checkRateLimit(ctx, ip, models.ClassAuth, keyPrefixIP, requestsPerWindow, window, privacy.AnonymizeIP(ip))
	if err != nil {
		return nil, err
	}
	if !ipRes.Allowed {
		return &models.AuthRateLimitResult{
			RateLimitResult: *ipRes,
		}, nil
	}

	return &models.AuthRateLimitResult{
		RateLimitResult: models.RateLimitResult{
			Allowed:    true,
			Limit:      requestsPerWindow,
			Remaining:  ipRes.Remaining,
			ResetAt:    ipRes.ResetAt,
			RetryAfter: 0,
		},
		RequiresCaptcha: failureRecord != nil && failureRecord.RequiresCaptcha,
		FailureCount:    0,
	}, nil
}

// RecordAuthFailure records a failed authentication attempt.
func (s *Service) RecordAuthFailure(ctx context.Context, identifier, ip string) (*models.AuthLockout, error) {
	key := fmt.Sprintf("%s:%s:%s", keyPrefixAuth, identifier, ip)
	current, err := s.authLockout.RecordFailure(ctx, key)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to record auth failure")
	}

	if current.FailureCount >= s.config.AuthLockout.HardLockThreshold {
		lockDuration := s.config.AuthLockout.HardLockDuration
		lockedUntil := time.Now().Add(lockDuration)
		current.LockedUntil = &lockedUntil
		err = s.authLockout.Update(ctx, current)
		if err != nil {
			return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to update auth lockout record")
		}
		s.logAudit(ctx, "auth_lockout_triggered",
			"identifier", identifier,
			"ip", ip,
			"locked_until", current.LockedUntil,
		)
	}

	// Require CAPTCHA after 3 consecutive lockouts within 24 hours
	if current.DailyFailures >= s.config.AuthLockout.CaptchaAfterLockouts {
		current.RequiresCaptcha = true
		err = s.authLockout.Update(ctx, current)
		if err != nil {
			return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to update auth lockout record for captcha")
		}
	}

	return current, nil
}

// ClearAuthFailures clears auth failure state after successful login.
func (s *Service) ClearAuthFailures(ctx context.Context, identifier, ip string) error {
	key := fmt.Sprintf("%s:%s:%s", keyPrefixAuth, identifier, ip)
	err := s.authLockout.Clear(ctx, key)
	if err != nil {
		return dErrors.Wrap(err, dErrors.CodeInternal, "failed to clear auth failures")
	}

	s.logAudit(ctx, "auth_lockout_cleared",
		"identifier", identifier,
		"ip", ip,
	)

	return nil
}

func (s *Service) GetProgressiveBackoff(failureCount int) time.Duration {
	if failureCount <= 0 {
		return 0
	}
	base := 250 * time.Millisecond
	delay := min(
		base*time.Duration(1<<(failureCount-1)), time.Second)
	return delay
}

// CheckAPIKeyQuota checks quota for partner API key.
func (s *Service) CheckAPIKeyQuota(ctx context.Context, apiKeyID string) (*models.APIKeyQuota, error) {
	quota, err := s.quotas.GetQuota(ctx, apiKeyID)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to get API key quota")
	}
	if quota == nil {
		return nil, dErrors.Wrap(fmt.Errorf("quota not found for API key %s", apiKeyID), dErrors.CodeNotFound, "quota not found")
	}
	return quota, nil
}

// CheckGlobalThrottle checks global request throttle for DDoS protection.
func (s *Service) CheckGlobalThrottle(ctx context.Context) (bool, error) {
	count, blocked, err := s.globalThrottle.IncrementGlobal(ctx)
	if err != nil {
		return false, dErrors.Wrap(err, dErrors.CodeInternal, "failed to increment global throttle")
	}

	// Log if we are blocking due to global throttle
	if blocked {
		s.logAudit(ctx, "global_throttle_triggered",
			"current_count", count,
			"global_limit", s.config.Global.GlobalPerSecond,
		)
	}

	return blocked, nil
}

// logAudit emits an audit event for rate limiting operations.
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
