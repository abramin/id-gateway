package cleanup

import (
	"context"
	"log/slog"
	"time"

	"credo/internal/ratelimit/config"
	"credo/internal/ratelimit/metrics"
)

// CleanupResult contains the results of a cleanup run (PRD-017 FR-8).
type CleanupResult struct {
	FailuresReset      int           // Number of window failure counts reset
	DailyFailuresReset int           // Number of daily failure counts reset
	Duration           time.Duration // Time taken for cleanup run
}

// AuthLockoutStore defines the subset of store operations needed for cleanup.
// This is kept local because it's a narrow interface specific to cleanup needs.
// The cutoff time is provided by the caller to keep business rules in the service layer.
type AuthLockoutStore interface {
	ResetFailureCount(ctx context.Context, cutoff time.Time) (failuresReset int, err error)
	ResetDailyFailures(ctx context.Context, cutoff time.Time) (failuresReset int, err error)
}

type Option func(*AuthLockoutCleanupService)

func WithLogger(logger *slog.Logger) Option {
	return func(s *AuthLockoutCleanupService) {
		if logger != nil {
			s.logger = logger
		}
	}
}

func WithInterval(interval time.Duration) Option {
	return func(s *AuthLockoutCleanupService) {
		if interval > 0 {
			s.interval = interval
		}
	}
}

func WithMetrics(m *metrics.Metrics) Option {
	return func(s *AuthLockoutCleanupService) {
		s.metrics = m
	}
}

// WithConfig sets the auth lockout config for calculating cutoff times.
func WithConfig(cfg *config.AuthLockoutConfig) Option {
	return func(s *AuthLockoutCleanupService) {
		if cfg != nil {
			s.config = cfg
		}
	}
}

// AuthLockoutCleanupService periodically resets expired lockout counters.
// This service owns the business rules for cutoff calculations (window duration, daily reset).
type AuthLockoutCleanupService struct {
	store    AuthLockoutStore
	logger   *slog.Logger
	interval time.Duration
	metrics  *metrics.Metrics
	config   *config.AuthLockoutConfig
}

func New(store AuthLockoutStore, opts ...Option) *AuthLockoutCleanupService {
	defaultCfg := config.DefaultConfig().AuthLockout
	service := &AuthLockoutCleanupService{
		store:    store,
		logger:   slog.Default(),
		interval: 15 * time.Minute,
		metrics:  nil,
		config:   &defaultCfg,
	}
	for _, opt := range opts {
		opt(service)
	}
	return service
}

func (s *AuthLockoutCleanupService) Start(ctx context.Context) error {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			startTime := time.Now()
			res, err := s.RunOnce(ctx)
			duration := time.Since(startTime)

			if err != nil {
				s.logger.Error("auth_lockout_cleanup_failed",
					"error", err,
					"duration_ms", duration.Milliseconds(),
				)
				if s.metrics != nil {
					s.metrics.RateLimitCleanupRunsTotal.WithLabelValues("error").Inc()
					s.metrics.RateLimitCleanupDurationSeconds.Observe(duration.Seconds())
				}
				continue
			}

			// Set duration in result
			res.Duration = duration

			s.logger.Info("auth_lockout_cleanup_completed",
				"failure_counts_reset", res.FailuresReset,
				"daily_failures_reset", res.DailyFailuresReset,
				"duration_ms", duration.Milliseconds(),
			)

			if s.metrics != nil {
				s.metrics.RateLimitCleanupFailuresResetTotal.Add(float64(res.FailuresReset))
				s.metrics.RateLimitCleanupDailyFailuresResetTotal.Add(float64(res.DailyFailuresReset))
				s.metrics.RateLimitCleanupRunsTotal.WithLabelValues("success").Inc()
				s.metrics.RateLimitCleanupDurationSeconds.Observe(duration.Seconds())
			}

		case <-ctx.Done():
			s.logger.Info("auth lockout cleanup worker stopping", "reason", ctx.Err())
			return ctx.Err()
		}
	}
}

// RunOnce executes a single cleanup run. Logging is handled by the caller (Start).
// This method owns the business rules for cutoff calculations:
//   - Window failures: reset records older than WindowDuration (default 15 min)
//   - Daily failures: reset records older than 24 hours
func (s *AuthLockoutCleanupService) RunOnce(ctx context.Context) (res *CleanupResult, err error) {
	now := time.Now()

	// Calculate cutoffs (business rules owned by this service, not the store)
	windowCutoff := now.Add(-s.config.WindowDuration)
	dailyCutoff := now.Add(-24 * time.Hour)

	failuresReset, err := s.store.ResetFailureCount(ctx, windowCutoff)
	if err != nil {
		return nil, err
	}
	dailyReset, err := s.store.ResetDailyFailures(ctx, dailyCutoff)
	if err != nil {
		return nil, err
	}
	return &CleanupResult{FailuresReset: failuresReset, DailyFailuresReset: dailyReset}, nil
}
