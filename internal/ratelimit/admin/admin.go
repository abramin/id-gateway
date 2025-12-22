package admin

import (
	"context"
	"fmt"
	"log/slog"

	"credo/internal/ratelimit/models"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	request "credo/pkg/platform/middleware/request"
)

// AllowlistStore defines the persistence interface for rate limit allowlist.
type AllowlistStore interface {
	// Add adds an identifier to the allowlist.
	Add(ctx context.Context, entry *models.AllowlistEntry) error

	// Remove removes an identifier from the allowlist.
	Remove(ctx context.Context, entryType models.AllowlistEntryType, identifier string) error

	// List returns all active allowlist entries.
	List(ctx context.Context) ([]*models.AllowlistEntry, error)
}

// BucketStore defines the persistence interface for rate limit bucket operations.
type BucketStore interface {
	// Reset clears the rate limit counter for a key.
	Reset(ctx context.Context, key string) error

	// GetCurrentCount returns the current request count for a key.
	GetCurrentCount(ctx context.Context, key string) (int, error)
}

// AuditPublisher defines the interface for publishing audit events.
type AuditPublisher interface {
	Emit(ctx context.Context, event audit.Event) error
}

// Service handles low-traffic administrative rate limit operations.
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

// AddToAllowlist adds an IP or user to the rate limit allowlist.
func (s *Service) AddToAllowlist(ctx context.Context, req *models.AddAllowlistRequest, adminUserID string) (*models.AllowlistEntry, error) {
	// TODO: Implement
	// 1. Validate request
	// 2. Create AllowlistEntry domain object
	// 3. Save to allowlist store
	// 4. Emit audit event "rate_limit_allowlist_added"
	return nil, dErrors.New(dErrors.CodeInternal, "not implemented")
}

// RemoveFromAllowlist removes an IP or user from the allowlist.
func (s *Service) RemoveFromAllowlist(ctx context.Context, req *models.RemoveAllowlistRequest) error {
	// TODO: Implement
	// 1. Validate request
	// 2. Remove from allowlist store
	// 3. Emit audit event "rate_limit_allowlist_removed"
	return dErrors.New(dErrors.CodeInternal, "not implemented")
}

// ListAllowlist returns all active allowlist entries.
func (s *Service) ListAllowlist(ctx context.Context) ([]*models.AllowlistEntry, error) {
	// TODO: Implement
	return nil, dErrors.New(dErrors.CodeInternal, "not implemented")
}

// ResetRateLimit resets the rate limit counter for an identifier.
func (s *Service) ResetRateLimit(ctx context.Context, req *models.ResetRateLimitRequest) error {
	// TODO: Implement
	// 1. Validate request
	// 2. Build key(s) to reset
	// 3. Call buckets.Reset() for each key
	// 4. Emit audit event "rate_limit_reset"
	return dErrors.New(dErrors.CodeInternal, "not implemented")
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
