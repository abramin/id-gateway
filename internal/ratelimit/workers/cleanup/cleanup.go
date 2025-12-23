package cleanup

import (
	"context"
	"log/slog"
	"time"

	"credo/internal/ratelimit/metrics"
)

type CleanupResult struct {
	FailuresReset      int
	DailyFailuresReset int
}

type AuthLockoutStore interface {
	ResetFailureCount(ctx context.Context) (failuresReset int, err error)
	ResetDailyFailures(ctx context.Context) (failuresReset int, err error)
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

type AuthLockoutCleanupService struct {
	store    AuthLockoutStore
	logger   *slog.Logger
	interval time.Duration
	metrics  *metrics.Metrics
}

func New(store AuthLockoutStore, opts ...Option) *AuthLockoutCleanupService {
	service := &AuthLockoutCleanupService{
		store:    store,
		logger:   slog.Default(),
		interval: 15 * time.Minute,
		metrics:  nil,
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
			if err != nil {
				s.logger.Error("auth lockout cleanup run failed", "error", err)
				continue
			}

			duration := time.Since(startTime).Seconds()
			if s.metrics != nil {
				s.metrics.RateLimitCleanupFailuresResetTotal.Add(float64(res.FailuresReset))
				s.metrics.RateLimitCleanupDailyFailuresResetTotal.Add(float64(res.DailyFailuresReset))
				s.metrics.RateLimitCleanupRunsTotal.WithLabelValues("success").Inc()
				s.metrics.RateLimitCleanupDurationSeconds.Observe(duration)
			}

		case <-ctx.Done():
			s.logger.Info("auth lockout cleanup worker stopping", "reason", ctx.Err())
			return ctx.Err()
		}
	}
}

func (s *AuthLockoutCleanupService) RunOnce(ctx context.Context) (res *CleanupResult, err error) {
	failuresReset, err := s.store.ResetFailureCount(ctx)
	if err != nil {
		return nil, err
	}
	s.logger.Info("auth lockout cleanup run completed", "failures_reset", failuresReset)
	dailyReset, err := s.store.ResetDailyFailures(ctx)
	if err != nil {
		return nil, err
	}
	s.logger.Info("auth lockout daily failures reset completed", "daily_failures_reset", dailyReset)
	return &CleanupResult{FailuresReset: failuresReset, DailyFailuresReset: dailyReset}, nil
}
