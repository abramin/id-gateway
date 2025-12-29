// Package observability provides audit logging helpers for the ratelimit module.
package observability

import (
	"context"
	"log/slog"

	id "credo/pkg/domain"
	"credo/pkg/platform/attrs"
	"credo/pkg/platform/audit"
	"credo/pkg/requestcontext"
)

// AuditPublisher emits audit events for security-relevant operations.
type AuditPublisher interface {
	Emit(ctx context.Context, event audit.Event) error
}

// LogAudit is a shared helper for logging audit events across ratelimit services.
// It logs to both the structured logger and the audit publisher if available.
func LogAudit(ctx context.Context, logger *slog.Logger, publisher AuditPublisher, event string, attrList ...any) {
	requestID := requestcontext.RequestID(ctx)

	// Add request ID for traceability
	if requestID != "" {
		attrList = append(attrList, "request_id", requestID)
	}

	// Add standard audit fields
	args := append(attrList, "event", event, "log_type", "audit")

	// Log to structured logger
	if logger != nil {
		logger.InfoContext(ctx, event, args...)
	}

	// Emit to audit publisher with enriched fields
	if publisher == nil {
		return
	}

	// Extract subject from common identifier fields (ip, identifier, user_id, client_id, api_key_id)
	subject := attrs.ExtractString(attrList, "identifier")
	if subject == "" {
		subject = attrs.ExtractString(attrList, "ip")
	}
	if subject == "" {
		subject = attrs.ExtractString(attrList, "user_id")
	}
	if subject == "" {
		subject = attrs.ExtractString(attrList, "client_id")
	}
	if subject == "" {
		subject = attrs.ExtractString(attrList, "api_key_id")
	}

	// Extract user_id if available
	userIDStr := attrs.ExtractString(attrList, "user_id")
	userID, _ := id.ParseUserID(userIDStr)

	// Extract reason from common fields
	reason := attrs.ExtractString(attrList, "reason")
	if reason == "" {
		reason = attrs.ExtractString(attrList, "bypass_type")
	}

	if err := publisher.Emit(ctx, audit.Event{
		Action:    event,
		Subject:   subject,
		UserID:    userID,
		RequestID: requestID,
		Reason:    reason,
		Decision:  "denied", // Rate limit events are typically denials
	}); err != nil && logger != nil {
		logger.WarnContext(ctx, "failed to emit audit event", "event", event, "error", err)
	}
}
