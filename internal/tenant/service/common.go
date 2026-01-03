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
	"credo/pkg/platform/audit/publishers/security"
	"credo/pkg/platform/sentinel"
	"credo/pkg/requestcontext"
)

// Store interfaces define persistence contracts.

type TenantStore interface {
	CreateIfNameAvailable(ctx context.Context, tenant *models.Tenant) error
	Update(ctx context.Context, tenant *models.Tenant) error
	Execute(ctx context.Context, tenantID id.TenantID, validate func(*models.Tenant) error, mutate func(*models.Tenant)) (*models.Tenant, error)
	FindByID(ctx context.Context, tenantID id.TenantID) (*models.Tenant, error)
	FindByName(ctx context.Context, name string) (*models.Tenant, error)
	Count(ctx context.Context) (int, error)
}

type ClientStore interface {
	Create(ctx context.Context, client *models.Client) error
	Update(ctx context.Context, client *models.Client) error
	Execute(ctx context.Context, clientID id.ClientID, validate func(*models.Client) error, mutate func(*models.Client)) (*models.Client, error)
	FindByID(ctx context.Context, clientID id.ClientID) (*models.Client, error)
	FindByTenantAndID(ctx context.Context, tenantID id.TenantID, clientID id.ClientID) (*models.Client, error)
	FindByOAuthClientID(ctx context.Context, oauthClientID string) (*models.Client, error)
	CountByTenant(ctx context.Context, tenantID id.TenantID) (int, error)
}

type UserCounter interface {
	CountByTenant(ctx context.Context, tenantID id.TenantID) (int, error)
}

// AuditPublisher is now the security publisher for tenant events.
// Tenant lifecycle events (create, deactivate, secret rotation) are security-relevant.
type AuditPublisher = *security.Publisher

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

// wrapStoreErr translates store errors into domain errors using the provided message selector.
func wrapStoreErr(err error, action string, msgSelector func(storeErrorMapping) string) error {
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
			return dErrors.Wrap(err, m.code, msgSelector(m))
		}
	}

	// Default: internal error
	return dErrors.Wrap(err, dErrors.CodeInternal, action)
}

// wrapClientErr translates store errors into client-specific domain errors.
func wrapClientErr(err error, action string) error {
	return wrapStoreErr(err, action, func(m storeErrorMapping) string { return m.clientMsg })
}

// wrapTenantErr translates store errors into tenant-specific domain errors.
func wrapTenantErr(err error, action string) error {
	return wrapStoreErr(err, action, func(m storeErrorMapping) string { return m.tenantMsg })
}

// auditEmitter handles audit logging and event emission.
type auditEmitter struct {
	logger    *slog.Logger
	publisher AuditPublisher
}

func newAuditEmitter(logger *slog.Logger, publisher AuditPublisher) *auditEmitter {
	return &auditEmitter{logger: logger, publisher: publisher}
}

func (e *auditEmitter) emit(ctx context.Context, event string, attributes ...any) error {
	attributes = e.enrichAttributes(ctx, attributes)
	e.logToText(ctx, event, attributes)
	return e.emitToAudit(ctx, event, attributes)
}

// Typed event emitters provide stronger typing for domain events.

func (e *auditEmitter) emitTenantCreated(ctx context.Context, evt models.TenantCreated) error {
	return e.emit(ctx, string(audit.EventTenantCreated), "tenant_id", evt.TenantID)
}

func (e *auditEmitter) emitTenantDeactivated(ctx context.Context, evt models.TenantDeactivated) error {
	return e.emit(ctx, string(audit.EventTenantDeactivated), "tenant_id", evt.TenantID)
}

func (e *auditEmitter) emitTenantReactivated(ctx context.Context, evt models.TenantReactivated) error {
	return e.emit(ctx, string(audit.EventTenantReactivated), "tenant_id", evt.TenantID)
}

func (e *auditEmitter) emitClientCreated(ctx context.Context, evt models.ClientCreated) error {
	return e.emit(ctx, string(audit.EventClientCreated),
		"tenant_id", evt.TenantID,
		"client_id", evt.ClientID,
		"client_name", evt.ClientName,
	)
}

func (e *auditEmitter) emitClientDeactivated(ctx context.Context, evt models.ClientDeactivated) error {
	return e.emit(ctx, string(audit.EventClientDeactivated),
		"client_id", evt.ClientID,
		"tenant_id", evt.TenantID,
	)
}

func (e *auditEmitter) emitClientReactivated(ctx context.Context, evt models.ClientReactivated) error {
	return e.emit(ctx, string(audit.EventClientReactivated),
		"client_id", evt.ClientID,
		"tenant_id", evt.TenantID,
	)
}

func (e *auditEmitter) emitClientSecretRotated(ctx context.Context, evt models.ClientSecretRotated) error {
	return e.emit(ctx, string(audit.EventClientSecretRotated),
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

func (e *auditEmitter) emitToAudit(ctx context.Context, event string, attributes []any) error {
	if e.publisher == nil {
		return dErrors.New(dErrors.CodeInternal, "audit publisher is required")
	}

	subject := resolveAuditSubject(attributes, attrs.ExtractString(attributes, "user_id"))

	// Security publisher is fire-and-forget with internal buffering and retry
	e.publisher.Emit(ctx, audit.SecurityEvent{
		Subject:   subject,
		Action:    event,
		RequestID: requestcontext.RequestID(ctx),
		Severity:  audit.SeverityInfo,
	})

	return nil
}

// resolveAuditSubject determines the audit subject from attributes.
// Priority: tenant_id > client_id > user_id (fallback).
func resolveAuditSubject(attributes []any, fallbackUserID string) string {
	if s := attrs.ExtractString(attributes, "tenant_id"); s != "" {
		return s
	}
	if s := attrs.ExtractString(attributes, "client_id"); s != "" {
		return s
	}
	return fallbackUserID
}
