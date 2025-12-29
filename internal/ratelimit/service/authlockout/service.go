// Package authlockout prevents brute-force authentication attacks (PRD-017 FR-2b).
//
// This service tracks failed login attempts per username+IP combination and
// enforces progressive penalties:
//   - Sliding window: 5 attempts per 15 minutes
//   - Hard lock: 15 minutes after 10 daily failures
//   - CAPTCHA requirement: after 3 consecutive lockouts in 24 hours
//
// Usage:
//
//	svc, _ := authlockout.New(store)
//	result, _ := svc.Check(ctx, username, clientIP)
//	if !result.Allowed {
//	    // Return 429 with Retry-After header
//	}
//	// After failed login:
//	svc.RecordFailure(ctx, username, clientIP)
//	// After successful login:
//	svc.Clear(ctx, username, clientIP)
//
// The composite key (username:IP) prevents cross-IP attacks while allowing
// legitimate multi-device access.
package authlockout

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"credo/internal/ratelimit/config"
	"credo/internal/ratelimit/models"
	"credo/internal/ratelimit/observability"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/privacy"
	"credo/pkg/requestcontext"
)

// Store is the persistence interface for auth lockout records.
type Store interface {
	RecordFailure(ctx context.Context, identifier string) (*models.AuthLockout, error)
	Get(ctx context.Context, identifier string) (*models.AuthLockout, error)
	Clear(ctx context.Context, identifier string) error
	IsLocked(ctx context.Context, identifier string) (bool, *time.Time, error)
	Update(ctx context.Context, record *models.AuthLockout) error
}

// Service tracks authentication failures and enforces lockout policies.
// Thread-safe for concurrent use by auth handlers.
type Service struct {
	store          Store
	auditPublisher observability.AuditPublisher
	logger         *slog.Logger
	config         *config.AuthLockoutConfig
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

// WithConfig overrides the default lockout configuration.
func WithConfig(cfg *config.AuthLockoutConfig) Option {
	return func(s *Service) {
		s.config = cfg
	}
}

// New creates an auth lockout service with the given store and options.
func New(store Store, opts ...Option) (*Service, error) {
	if store == nil {
		return nil, errors.New("auth lockout store is required")
	}

	defaultCfg := config.DefaultConfig().AuthLockout
	svc := &Service{
		store:  store,
		config: &defaultCfg,
	}

	for _, opt := range opts {
		opt(svc)
	}

	return svc, nil
}

// Check determines if an authentication attempt should be allowed.
// Call this BEFORE validating credentials to enforce rate limits.
//
// Returns:
//   - Allowed=true with progressive backoff delay (RetryAfter in milliseconds)
//   - Allowed=false if hard locked or sliding window exceeded
//   - RequiresCaptcha=true after 3 consecutive lockouts in 24 hours
//
// Uses constant-time behavior to prevent timing-based user enumeration.
func (s *Service) Check(ctx context.Context, identifier, ip string) (*models.AuthRateLimitResult, error) {
	key := models.NewAuthLockoutKey(identifier, ip).String()
	failureRecord, err := s.store.Get(ctx, key)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to get auth lockout record")
	}

	// Use zero-valued record for consistent code path (prevents timing-based enumeration).
	// All checks execute regardless of record existence to ensure constant-time behavior.
	record := failureRecord
	if record == nil {
		record = &models.AuthLockout{}
	}

	now := requestcontext.Now(ctx)

	// Check if currently hard-locked (FR-2b: "hard lock for 15 minutes")
	if record.IsLockedAt(now) {
		retryAfter := max(int(record.LockedUntil.Sub(now).Seconds()), 0)
		observability.LogAudit(ctx, s.logger, s.auditPublisher, "auth_lockout_triggered",
			"identifier", identifier,
			"ip", privacy.AnonymizeIP(ip),
			"locked_until", record.LockedUntil,
		)
		return &models.AuthRateLimitResult{
			RateLimitResult: models.RateLimitResult{
				Allowed:    false,
				ResetAt:    *record.LockedUntil,
				RetryAfter: retryAfter,
			},
			RequiresCaptcha: record.RequiresCaptcha,
			FailureCount:    record.FailureCount,
		}, nil
	}

	// Check failure count against sliding window (FR-2b: "5 attempts/15 min")
	if record.IsAttemptLimitReached(s.config.AttemptsPerWindow) {
		// Block - too many attempts in window
		resetAt := s.config.BackoffPolicy().ResetTime(record.LastFailureAt)
		retryAfter := max(int(resetAt.Sub(now).Seconds()), 0)
		return &models.AuthRateLimitResult{
			RateLimitResult: models.RateLimitResult{
				Allowed:    false,
				ResetAt:    resetAt,
				RetryAfter: retryAfter,
			},
			RequiresCaptcha: record.RequiresCaptcha,
			FailureCount:    record.FailureCount,
		}, nil
	}

	// Apply progressive backoff (FR-2b: "250ms → 500ms → 1s")
	// Calculate backoff even for zero failures to maintain constant-time behavior
	delay := s.GetProgressiveBackoff(record.FailureCount)
	remaining := min(record.RemainingAttempts(s.config.AttemptsPerWindow), s.config.AttemptsPerWindow)

	return &models.AuthRateLimitResult{
		RateLimitResult: models.RateLimitResult{
			Allowed:    true,
			Limit:      s.config.AttemptsPerWindow,
			Remaining:  remaining,
			ResetAt:    now.Add(s.config.WindowDuration),
			RetryAfter: int(delay.Milliseconds()),
		},
		RequiresCaptcha: record.RequiresCaptcha,
		FailureCount:    record.FailureCount,
	}, nil
}

// RecordFailure increments failure counters after a failed authentication attempt.
// Call this AFTER credential validation fails.
//
// Side effects:
//   - Increments window and daily failure counts
//   - Applies hard lock if daily threshold (10 failures) is reached
//   - Sets CAPTCHA requirement after 3 consecutive lockouts in 24 hours
//   - Emits audit event when hard lock is triggered
func (s *Service) RecordFailure(ctx context.Context, identifier, ip string) (*models.AuthLockout, error) {
	key := models.NewAuthLockoutKey(identifier, ip).String()
	current, err := s.store.RecordFailure(ctx, key)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to record auth failure")
	}

	now := requestcontext.Now(ctx)

	// Compute state transitions upfront for clarity
	shouldHardLock := current.ShouldHardLock(s.config.HardLockThreshold)
	shouldRequireCaptcha := current.ShouldRequireCaptcha(s.config.CaptchaAfterLockouts) && !current.RequiresCaptcha

	if shouldHardLock {
		current.ApplyHardLock(s.config.HardLockDuration, now)
		observability.LogAudit(ctx, s.logger, s.auditPublisher, "auth_lockout_triggered",
			"identifier", identifier,
			"ip", privacy.AnonymizeIP(ip),
			"locked_until", current.LockedUntil,
		)
	}

	if shouldRequireCaptcha {
		current.MarkRequiresCaptcha()
	}

	if shouldHardLock || shouldRequireCaptcha {
		if err = s.store.Update(ctx, current); err != nil {
			return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to update auth lockout record")
		}
	}

	return current, nil
}

// Clear resets the lockout record after successful authentication.
// Call this after the user successfully logs in to reset their failure window.
// Does NOT reset daily failure counts or CAPTCHA requirements (those reset via cleanup worker).
func (s *Service) Clear(ctx context.Context, identifier, ip string) error {
	key := models.NewAuthLockoutKey(identifier, ip).String()
	err := s.store.Clear(ctx, key)
	if err != nil {
		return dErrors.Wrap(err, dErrors.CodeInternal, "failed to clear auth failures")
	}

	observability.LogAudit(ctx, s.logger, s.auditPublisher, "auth_lockout_cleared",
		"identifier", identifier,
		"ip", privacy.AnonymizeIP(ip),
	)

	return nil
}

// GetProgressiveBackoff calculates the delay before the next attempt.
// Implements exponential backoff: 250ms → 500ms → 1s (PRD-017 FR-2b).
func (s *Service) GetProgressiveBackoff(failureCount int) time.Duration {
	return s.config.CalculateBackoff(failureCount)
}
