package authlockout

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
)

const keyPrefixAuth = "auth"

type Store interface {
	RecordFailure(ctx context.Context, identifier string) (*models.AuthLockout, error)
	Get(ctx context.Context, identifier string) (*models.AuthLockout, error)
	Clear(ctx context.Context, identifier string) error
	IsLocked(ctx context.Context, identifier string) (bool, *time.Time, error)
	Update(ctx context.Context, record *models.AuthLockout) error
}

type AuditPublisher interface {
	Emit(ctx context.Context, event audit.Event) error
}

type Service struct {
	store          Store
	auditPublisher AuditPublisher
	logger         *slog.Logger
	config         *config.AuthLockoutConfig
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

func WithConfig(cfg *config.AuthLockoutConfig) Option {
	return func(s *Service) {
		s.config = cfg
	}
}

func New(store Store, opts ...Option) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("auth lockout store is required")
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

func (s *Service) Check(ctx context.Context, identifier, ip string) (*models.AuthRateLimitResult, error) {
	key := fmt.Sprintf("%s:%s:%s", keyPrefixAuth, identifier, ip)
	failureRecord, err := s.store.Get(ctx, key)
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
	if failureRecord != nil && failureRecord.FailureCount >= s.config.AttemptsPerWindow {
		remaining := s.config.AttemptsPerWindow - failureRecord.FailureCount
		if remaining <= 0 {
			// Block - too many attempts in window
			resetAt := failureRecord.LastFailureAt.Add(s.config.WindowDuration)
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
				Limit:      s.config.AttemptsPerWindow,
				Remaining:  s.config.AttemptsPerWindow - failureRecord.FailureCount,
				ResetAt:    time.Now().Add(s.config.WindowDuration),
				RetryAfter: int(delay.Milliseconds()),
			},
			RequiresCaptcha: failureRecord.RequiresCaptcha,
			FailureCount:    failureRecord.FailureCount,
		}, nil
	}

	return &models.AuthRateLimitResult{
		RateLimitResult: models.RateLimitResult{
			Allowed:    true,
			Limit:      s.config.AttemptsPerWindow,
			Remaining:  s.config.AttemptsPerWindow,
			ResetAt:    time.Now().Add(s.config.WindowDuration),
			RetryAfter: 0,
		},
		RequiresCaptcha: failureRecord != nil && failureRecord.RequiresCaptcha,
		FailureCount:    0,
	}, nil
}

// RecordFailure records a failed authentication attempt.
func (s *Service) RecordFailure(ctx context.Context, identifier, ip string) (*models.AuthLockout, error) {
	key := fmt.Sprintf("%s:%s:%s", keyPrefixAuth, identifier, ip)
	current, err := s.store.RecordFailure(ctx, key)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to record auth failure")
	}

	if current.FailureCount >= s.config.HardLockThreshold {
		lockDuration := s.config.HardLockDuration
		lockedUntil := time.Now().Add(lockDuration)
		current.LockedUntil = &lockedUntil
		err = s.store.Update(ctx, current)
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
	if current.DailyFailures >= s.config.CaptchaAfterLockouts {
		current.RequiresCaptcha = true
		err = s.store.Update(ctx, current)
		if err != nil {
			return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to update auth lockout record for captcha")
		}
	}

	return current, nil
}

func (s *Service) Clear(ctx context.Context, identifier, ip string) error {
	key := fmt.Sprintf("%s:%s:%s", keyPrefixAuth, identifier, ip)
	err := s.store.Clear(ctx, key)
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
