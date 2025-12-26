package service

import (
	"context"
	"errors"
	"log/slog"

	"credo/internal/tenant/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/attrs"
	"credo/pkg/platform/audit"
	request "credo/pkg/platform/middleware/request"
	"credo/pkg/platform/sentinel"
)

// Store interfaces define persistence contracts.

type TenantStore interface {
	CreateIfNameAvailable(ctx context.Context, tenant *models.Tenant) error
	Update(ctx context.Context, tenant *models.Tenant) error
	FindByID(ctx context.Context, tenantID id.TenantID) (*models.Tenant, error)
	FindByName(ctx context.Context, name string) (*models.Tenant, error)
	Count(ctx context.Context) (int, error)
}

type ClientStore interface {
	Create(ctx context.Context, client *models.Client) error
	Update(ctx context.Context, client *models.Client) error
	FindByID(ctx context.Context, clientID id.ClientID) (*models.Client, error)
	FindByTenantAndID(ctx context.Context, tenantID id.TenantID, clientID id.ClientID) (*models.Client, error)
	FindByOAuthClientID(ctx context.Context, oauthClientID string) (*models.Client, error)
	CountByTenant(ctx context.Context, tenantID id.TenantID) (int, error)
}

type UserCounter interface {
	CountByTenant(ctx context.Context, tenantID id.TenantID) (int, error)
}

type AuditPublisher interface {
	Emit(ctx context.Context, base audit.Event) error
}

// ID validation helpers reduce repetition in service methods.

func requireClientID(clientID id.ClientID) error {
	if clientID.IsNil() {
		return dErrors.New(dErrors.CodeBadRequest, "client ID required")
	}
	return nil
}

func requireTenantID(tenantID id.TenantID) error {
	if tenantID.IsNil() {
		return dErrors.New(dErrors.CodeBadRequest, "tenant ID required")
	}
	return nil
}

// Error wrapping helpers translate sentinel errors to domain errors.

func wrapClientErr(err error, action string) error {
	if errors.Is(err, sentinel.ErrNotFound) {
		return dErrors.New(dErrors.CodeNotFound, "client not found")
	}
	return dErrors.Wrap(err, dErrors.CodeInternal, action)
}

func wrapTenantErr(err error, action string) error {
	if errors.Is(err, sentinel.ErrNotFound) {
		return dErrors.New(dErrors.CodeNotFound, "tenant not found")
	}
	return dErrors.Wrap(err, dErrors.CodeInternal, action)
}

// auditEmitter handles audit logging and event emission.
type auditEmitter struct {
	logger    *slog.Logger
	publisher AuditPublisher
}

func newAuditEmitter(logger *slog.Logger, publisher AuditPublisher) *auditEmitter {
	return &auditEmitter{logger: logger, publisher: publisher}
}

func (e *auditEmitter) emit(ctx context.Context, event string, attributes ...any) {
	attributes = e.enrichAttributes(ctx, attributes)
	e.logToText(ctx, event, attributes)
	e.emitToAudit(ctx, event, attributes)
}

func (e *auditEmitter) enrichAttributes(ctx context.Context, attributes []any) []any {
	if requestID := request.GetRequestID(ctx); requestID != "" {
		attributes = append(attributes, "request_id", requestID)
	}
	return attributes
}

func (e *auditEmitter) logToText(ctx context.Context, event string, attributes []any) {
	if e.logger == nil {
		return
	}
	args := append(attributes, "event", event, "log_type", "audit")
	e.logger.InfoContext(ctx, event, args...)
}

func (e *auditEmitter) emitToAudit(ctx context.Context, event string, attributes []any) {
	if e.publisher == nil {
		return
	}
	userIDStr := attrs.ExtractString(attributes, "user_id")
	userID, err := id.ParseUserID(userIDStr)
	if err != nil && userIDStr != "" && e.logger != nil {
		e.logger.WarnContext(ctx, "failed to parse user_id for audit event",
			"user_id", userIDStr,
			"event", event,
			"error", err,
		)
	}
	if err := e.publisher.Emit(ctx, audit.Event{
		UserID:  userID,
		Subject: userIDStr,
		Action:  event,
	}); err != nil && e.logger != nil {
		e.logger.ErrorContext(ctx, "failed to emit audit event",
			"event", event,
			"error", err,
		)
	}
}
