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
	"credo/pkg/platform/sentinel"
	"credo/pkg/requestcontext"
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

// Error mapping: translates store/sentinel errors into domain errors.

// storeErrorMapping defines how a sentinel error maps to a domain error.
type storeErrorMapping struct {
	sentinel  error
	code      dErrors.Code
	clientMsg string
	tenantMsg string
}

// storeErrorMappings defines error translations in priority order.
// First match wins; more specific errors should come first.
var storeErrorMappings = []storeErrorMapping{
	{sentinel.ErrNotFound, dErrors.CodeNotFound, "client not found", "tenant not found"},
	{sentinel.ErrAlreadyUsed, dErrors.CodeConflict, "client already exists", "tenant name already exists"},
	{sentinel.ErrInvalidState, dErrors.CodeConflict, "invalid client state", "invalid tenant state"},
}

// wrapClientErr translates store errors into client-specific domain errors.
func wrapClientErr(err error, action string) error {
	if err == nil {
		return nil
	}

	// Pass through existing domain errors
	var de *dErrors.Error
	if errors.As(err, &de) {
		return err
	}

	// Check mappings in order
	for _, m := range storeErrorMappings {
		if errors.Is(err, m.sentinel) {
			return dErrors.Wrap(err, m.code, m.clientMsg)
		}
	}

	// Default: internal error
	return dErrors.Wrap(err, dErrors.CodeInternal, action)
}

// wrapTenantErr translates store errors into tenant-specific domain errors.
func wrapTenantErr(err error, action string) error {
	if err == nil {
		return nil
	}

	// Pass through existing domain errors
	var de *dErrors.Error
	if errors.As(err, &de) {
		return err
	}

	// Check mappings in order
	for _, m := range storeErrorMappings {
		if errors.Is(err, m.sentinel) {
			return dErrors.Wrap(err, m.code, m.tenantMsg)
		}
	}

	// Default: internal error
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

// Typed event emitters provide stronger typing for domain events.

func (e *auditEmitter) emitTenantCreated(ctx context.Context, evt models.TenantCreated) {
	e.emit(ctx, string(audit.EventTenantCreated), "tenant_id", evt.TenantID)
}

func (e *auditEmitter) emitTenantDeactivated(ctx context.Context, evt models.TenantDeactivated) {
	e.emit(ctx, string(audit.EventTenantDeactivated), "tenant_id", evt.TenantID)
}

func (e *auditEmitter) emitTenantReactivated(ctx context.Context, evt models.TenantReactivated) {
	e.emit(ctx, string(audit.EventTenantReactivated), "tenant_id", evt.TenantID)
}

func (e *auditEmitter) emitClientCreated(ctx context.Context, evt models.ClientCreated) {
	e.emit(ctx, string(audit.EventClientCreated),
		"tenant_id", evt.TenantID,
		"client_id", evt.ClientID,
		"client_name", evt.ClientName,
	)
}

func (e *auditEmitter) emitClientDeactivated(ctx context.Context, evt models.ClientDeactivated) {
	e.emit(ctx, string(audit.EventClientDeactivated),
		"client_id", evt.ClientID,
		"tenant_id", evt.TenantID,
	)
}

func (e *auditEmitter) emitClientReactivated(ctx context.Context, evt models.ClientReactivated) {
	e.emit(ctx, string(audit.EventClientReactivated),
		"client_id", evt.ClientID,
		"tenant_id", evt.TenantID,
	)
}

func (e *auditEmitter) emitClientSecretRotated(ctx context.Context, evt models.ClientSecretRotated) {
	e.emit(ctx, string(audit.EventClientSecretRotated),
		"tenant_id", evt.TenantID,
		"client_id", evt.ClientID,
	)
}

func (e *auditEmitter) enrichAttributes(ctx context.Context, attributes []any) []any {
	if requestID := requestcontext.RequestID(ctx); requestID != "" {
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

	// Extract admin user who performed the action
	userIDStr := attrs.ExtractString(attributes, "user_id")
	userID, err := id.ParseUserID(userIDStr)
	if err != nil && userIDStr != "" && e.logger != nil {
		e.logger.WarnContext(ctx, "failed to parse user_id for audit event",
			"user_id", userIDStr,
			"event", event,
			"error", err,
		)
	}

	// Subject is the affected entity (tenant_id or client_id for searchability)
	subject := attrs.ExtractString(attributes, "tenant_id")
	if subject == "" {
		subject = attrs.ExtractString(attributes, "client_id")
	}
	if subject == "" {
		subject = userIDStr // Fallback to user_id if no entity ID
	}

	requestID := requestcontext.RequestID(ctx)

	if err := e.publisher.Emit(ctx, audit.Event{
		UserID:    userID,
		Subject:   subject,
		Action:    event,
		RequestID: requestID,
	}); err != nil && e.logger != nil {
		e.logger.ErrorContext(ctx, "failed to emit audit event",
			"event", event,
			"error", err,
		)
	}
}
