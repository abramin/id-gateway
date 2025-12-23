package admin

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"credo/internal/ratelimit/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/audit"
	request "credo/pkg/platform/middleware/request"
)

type AllowlistStore interface {
	Add(ctx context.Context, entry *models.AllowlistEntry) error
	Remove(ctx context.Context, entryType models.AllowlistEntryType, identifier string) error
	List(ctx context.Context) ([]*models.AllowlistEntry, error)
}

type BucketStore interface {
	Reset(ctx context.Context, key string) error
	GetCurrentCount(ctx context.Context, key string) (int, error)
}

type AuditPublisher interface {
	Emit(ctx context.Context, event audit.Event) error
}

type Service struct {
	allowlist      AllowlistStore
	buckets        BucketStore
	auditPublisher AuditPublisher
	logger         *slog.Logger
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

func New(
	allowlist AllowlistStore,
	buckets BucketStore,
	opts ...Option,
) (*Service, error) {
	if allowlist == nil {
		return nil, fmt.Errorf("allowlist store is required")
	}
	if buckets == nil {
		return nil, fmt.Errorf("buckets store is required")
	}

	svc := &Service{
		allowlist: allowlist,
		buckets:   buckets,
	}

	for _, opt := range opts {
		opt(svc)
	}

	return svc, nil
}

func (s *Service) AddToAllowlist(ctx context.Context, req *models.AddAllowlistRequest, adminUserID id.UserID) (*models.AllowlistEntry, error) {
	req.Normalize()
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("invalid add allowlist request: %w", err)
	}

	entry, err := models.NewAllowlistEntry(req.Type, req.Identifier, req.Reason, adminUserID, req.ExpiresAt, time.Now())
	if err != nil {
		return nil, fmt.Errorf("failed to create allowlist entry: %w", err)
	}

	if err := s.allowlist.Add(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to add to allowlist: %w", err)
	}

	s.logAudit(ctx, "rate_limit_allowlist_added",
		"identifier", entry.Identifier,
		"type", entry.Type,
		"expires_at", entry.ExpiresAt,
		"admin_user_id", adminUserID,
	)
	return entry, nil
}

func (s *Service) RemoveFromAllowlist(ctx context.Context, req *models.RemoveAllowlistRequest) error {
	if err := req.Validate(); err != nil {
		return fmt.Errorf("invalid remove allowlist request: %w", err)
	}

	if err := s.allowlist.Remove(ctx, req.Type, req.Identifier); err != nil {
		return fmt.Errorf("failed to remove from allowlist: %w", err)
	}

	s.logAudit(ctx, "rate_limit_allowlist_removed",
		"identifier", req.Identifier,
		"type", req.Type,
	)
	return nil
}

func (s *Service) ListAllowlist(ctx context.Context) ([]*models.AllowlistEntry, error) {
	entries, err := s.allowlist.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list allowlist entries: %w", err)
	}
	return entries, nil
}

func (s *Service) ResetRateLimit(ctx context.Context, req *models.ResetRateLimitRequest) error {
	req.Normalize()
	if err := req.Validate(); err != nil {
		return fmt.Errorf("invalid reset rate limit request: %w", err)
	}
	keys := []string{}
	sanitizedID := models.SanitizeKeySegment(req.Identifier)
	switch req.Type {
	case models.AllowlistTypeIP:
		keys = append(keys, fmt.Sprintf("rl:ip:%s", sanitizedID))
	case models.AllowlistTypeUserID:
		keys = append(keys, fmt.Sprintf("rl:user:%s", sanitizedID))
	default:
		return fmt.Errorf("unknown identifier type: %s", req.Type)
	}

	for _, key := range keys {
		if err := s.buckets.Reset(ctx, key); err != nil {
			return fmt.Errorf("failed to reset rate limit for key %s: %w", key, err)
		}
	}

	s.logAudit(ctx, "rate_limit_reset",
		"identifier", req.Identifier,
		"type", req.Type,
		"class", req.Class,
	)
	return nil
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
