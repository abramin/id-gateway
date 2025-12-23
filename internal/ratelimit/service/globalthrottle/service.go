package globalthrottle

import (
	"context"
	"fmt"
	"log/slog"

	"credo/internal/ratelimit/config"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	request "credo/pkg/platform/middleware/request"
)

type Store interface {
	IncrementGlobal(ctx context.Context) (count int, blocked bool, err error)
	GetGlobalCount(ctx context.Context) (count int, err error)
}

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
		s.logAudit(ctx, "global_throttle_triggered",
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
