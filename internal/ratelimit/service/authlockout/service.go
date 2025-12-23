package authlockout

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"credo/internal/ratelimit/config"
	"credo/internal/ratelimit/models"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	request "credo/pkg/platform/middleware/request"
)


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

	now := time.Now()

	// Check if currently hard-locked (FR-2b: "hard lock for 15 minutes")
	if record.IsLocked() {
		retryAfter := int(time.Until(*record.LockedUntil).Seconds())
		s.logAudit(ctx, "auth_lockout_triggered",
			"identifier", identifier,
			"ip", ip,
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
		resetAt := s.config.ResetTime(record.LastFailureAt)
		return &models.AuthRateLimitResult{
			RateLimitResult: models.RateLimitResult{
				Allowed:    false,
				ResetAt:    resetAt,
				RetryAfter: int(time.Until(resetAt).Seconds()),
			},
			RequiresCaptcha: record.RequiresCaptcha,
			FailureCount:    record.FailureCount,
		}, nil
	}

	// Apply progressive backoff (FR-2b: "250ms → 500ms → 1s")
	// Calculate backoff even for zero failures to maintain constant-time behavior
	delay := s.GetProgressiveBackoff(record.FailureCount)
	remaining := record.RemainingAttempts(s.config.AttemptsPerWindow)
	if remaining > s.config.AttemptsPerWindow {
		remaining = s.config.AttemptsPerWindow
	}

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

func (s *Service) RecordFailure(ctx context.Context, identifier, ip string) (*models.AuthLockout, error) {
	key := models.NewAuthLockoutKey(identifier, ip).String()
	current, err := s.store.RecordFailure(ctx, key)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to record auth failure")
	}

	needsUpdate := false
	now := time.Now()

	// Check if hard lock threshold reached
	if current.ShouldHardLock(s.config.HardLockThreshold) {
		current.ApplyHardLock(s.config.HardLockDuration, now)
		needsUpdate = true
		s.logAudit(ctx, "auth_lockout_triggered",
			"identifier", identifier,
			"ip", ip,
			"locked_until", current.LockedUntil,
		)
	}

	// Require CAPTCHA after consecutive lockouts within 24 hours
	if current.ShouldRequireCaptcha(s.config.CaptchaAfterLockouts) && !current.RequiresCaptcha {
		current.MarkRequiresCaptcha()
		needsUpdate = true
	}

	if needsUpdate {
		if err = s.store.Update(ctx, current); err != nil {
			return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to update auth lockout record")
		}
	}

	return current, nil
}

func (s *Service) Clear(ctx context.Context, identifier, ip string) error {
	key := models.NewAuthLockoutKey(identifier, ip).String()
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
	return s.config.CalculateBackoff(failureCount)
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
