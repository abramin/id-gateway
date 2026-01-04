package audit

import (
	"context"
	"log/slog"

	id "credo/pkg/domain"
	"credo/pkg/platform/attrs"
	"credo/pkg/requestcontext"
)

// Emitter is the interface for audit event emission.
// Satisfied by publisher.Publisher.
type Emitter interface {
	Emit(ctx context.Context, event Event) error
}

// Logger provides structured audit logging with optional event emission.
// Use this in services to standardize audit logging patterns.
type Logger struct {
	textLogger *slog.Logger
	emitter    Emitter
}

// NewLogger creates an audit logger.
// textLogger is used for structured logging; emitter is optional for event persistence.
func NewLogger(textLogger *slog.Logger, emitter Emitter) *Logger {
	return &Logger{
		textLogger: textLogger,
		emitter:    emitter,
	}
}

// Log logs an audit event to text and optionally emits to the audit store.
// Automatically enriches with request_id from context.
//
// Usage:
//
//	logger.Log(ctx, "user_created", "user_id", userID.String(), "email", email)
func (l *Logger) Log(ctx context.Context, event string, attributes ...any) {
	// Enrich with request_id from context
	requestID := requestcontext.RequestID(ctx)
	if requestID != "" {
		attributes = append(attributes, "request_id", requestID)
	}

	// Log to text
	l.logToText(ctx, event, attributes)

	// Emit to audit store
	l.emitToAudit(ctx, event, requestID, attributes)
}

func (l *Logger) logToText(ctx context.Context, event string, attributes []any) {
	if l.textLogger == nil {
		return
	}
	args := append(attributes, "event", event, "log_type", "audit")
	l.textLogger.InfoContext(ctx, event, args...)
}

func (l *Logger) emitToAudit(ctx context.Context, event, requestID string, attributes []any) {
	if l.emitter == nil {
		return
	}

	// Extract known fields from attributes
	userIDStr := attrs.ExtractString(attributes, "user_id")
	email := attrs.ExtractString(attributes, "email")

	// Best-effort user ID parsing - ignore parse errors for audit
	userID, _ := id.ParseUserID(userIDStr) //nolint:errcheck // best-effort extraction for audit

	err := l.emitter.Emit(ctx, Event{
		UserID:    userID,
		Subject:   userIDStr,
		Action:    event,
		Email:     email,
		RequestID: requestID,
	})
	if err != nil && l.textLogger != nil {
		l.textLogger.ErrorContext(ctx, "failed to emit audit event",
			"error", err,
			"event", event,
		)
	}
}
