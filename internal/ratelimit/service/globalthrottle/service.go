package globalthrottle

import (
	"context"
	"fmt"
	"log/slog"

	"credo/internal/ratelimit/config"
	"credo/internal/ratelimit/observability"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
)

// Store manages global request throttling counters.
type Store interface {
	IncrementGlobal(ctx context.Context) (count int, blocked bool, err error)
	GetGlobalCount(ctx context.Context) (count int, err error)
}

// AuditPublisher emits audit events for security-relevant operations.
type AuditPublisher interface {
	Emit(ctx context.Context, event audit.Event) error
}

type Service struct {
	store          Store
	auditPublisher AuditPublisher
	logger         *slog.Logger
	config         *config.GlobalLimit
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

func WithConfig(cfg *config.GlobalLimit) Option {
	return func(s *Service) {
		s.config = cfg
	}
}

func New(store Store, opts ...Option) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("global throttle store is required")
	}

	defaultCfg := config.DefaultConfig().Global
	svc := &Service{
		store:  store,
		config: &defaultCfg,
	}

	for _, opt := range opts {
		opt(svc)
	}

	return svc, nil
}

// Check returns whether the request is allowed (true = allow, false = block).
// It increments the global counter and checks against the configured limit.
func (s *Service) Check(ctx context.Context) (bool, error) {
	count, blocked, err := s.store.IncrementGlobal(ctx)
	if err != nil {
		return false, dErrors.Wrap(err, dErrors.CodeInternal, "failed to increment global throttle")
	}

	if blocked {
		observability.LogAudit(ctx, s.logger, s.auditPublisher, "global_throttle_triggered",
			"current_count", count,
			"global_limit", s.config.GlobalPerSecond,
		)
	}

	// Return allowed semantics: !blocked means allowed
	return !blocked, nil
}

func (s *Service) GetCount(ctx context.Context) (int, error) {
	count, err := s.store.GetGlobalCount(ctx)
	if err != nil {
		return 0, dErrors.Wrap(err, dErrors.CodeInternal, "failed to get global count")
	}
	return count, nil
}
