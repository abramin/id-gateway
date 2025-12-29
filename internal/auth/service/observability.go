package service

import (
	"context"

	id "credo/pkg/domain"
	"credo/pkg/platform/attrs"
	"credo/pkg/platform/audit"
	request "credo/pkg/platform/middleware/request"
)

// Observability helpers for logging, auditing, and metrics.
// These methods are on *Service to access logger, auditPublisher, and metrics.

func (s *Service) logAudit(ctx context.Context, event string, attributes ...any) {
	// Add request_id from context if available
	requestID := request.GetRequestID(ctx)
	if requestID != "" {
		attributes = append(attributes, "request_id", requestID)
	}
	args := append(attributes, "event", event, "log_type", "audit")
	if s.logger != nil {
		s.logger.InfoContext(ctx, event, args...)
	}
	if s.auditPublisher == nil {
		return
	}
	userIDStr := attrs.ExtractString(attributes, "user_id")
	userID, _ := id.ParseUserID(userIDStr) // Best-effort for audit - ignore parse errors

	// PRD-001B: Extract email for audit enrichment
	email := attrs.ExtractString(attributes, "email")

	err := s.auditPublisher.Emit(ctx, audit.Event{
		UserID:    userID,
		Subject:   userIDStr,
		Action:    event,
		Email:     email,
		RequestID: requestID,
	})
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to emit audit event", "error", err)
	}
}

// authFailureAttrs holds parsed attributes for auth failure events.
// Extracted once and reused for both logging and audit emission.
type authFailureAttrs struct {
	requestID string
	userIDStr string
	userID    id.UserID
	email     string
	clientID  string
}

// parseAuthFailureAttrs extracts common attributes from the variadic list.
func parseAuthFailureAttrs(ctx context.Context, attributes []any) authFailureAttrs {
	userIDStr := attrs.ExtractString(attributes, "user_id")
	userID, _ := id.ParseUserID(userIDStr)
	return authFailureAttrs{
		requestID: request.GetRequestID(ctx),
		userIDStr: userIDStr,
		userID:    userID,
		email:     attrs.ExtractString(attributes, "email"),
		clientID:  attrs.ExtractString(attributes, "client_id"),
	}
}

func (s *Service) authFailure(ctx context.Context, reason string, isError bool, attributes ...any) {
	parsed := parseAuthFailureAttrs(ctx, attributes)
	s.logAuthFailure(ctx, reason, isError, parsed, attributes)
	s.emitAuthFailure(ctx, reason, parsed)
	if s.metrics != nil {
		s.metrics.IncrementAuthFailures()
	}
}

func (s *Service) logAuthFailure(ctx context.Context, reason string, isError bool, parsed authFailureAttrs, attributes []any) {
	if s.logger == nil {
		return
	}
	// Add request_id from context if available
	if parsed.requestID != "" {
		attributes = append(attributes, "request_id", parsed.requestID)
	}
	args := append(attributes, "event", audit.EventAuthFailed, "reason", reason, "log_type", "standard")
	if isError {
		s.logger.ErrorContext(ctx, string(audit.EventAuthFailed), args...)
		return
	}
	s.logger.WarnContext(ctx, string(audit.EventAuthFailed), args...)
}

// emitAuthFailure emits auth failure events to the audit store for compliance tracking.
func (s *Service) emitAuthFailure(ctx context.Context, reason string, parsed authFailureAttrs) {
	if s.auditPublisher == nil {
		return
	}

	if err := s.auditPublisher.Emit(ctx, audit.Event{
		UserID:          parsed.userID,
		Subject:         parsed.userIDStr,
		Action:          string(audit.EventAuthFailed),
		Reason:          reason,
		Decision:        "denied",
		RequestingParty: parsed.clientID,
		Email:           parsed.email,
		RequestID:       parsed.requestID,
	}); err != nil && s.logger != nil {
		s.logger.ErrorContext(ctx, "failed to emit auth failure audit event", "error", err)
	}
}

// incrementUserCreated increments the users created metric if metrics are enabled
func (s *Service) incrementUserCreated() {
	if s.metrics != nil {
		s.metrics.IncrementUsersCreated()
	}
}

// incrementActiveSession increments the active sessions metric if metrics are enabled
func (s *Service) incrementActiveSession() {
	if s.metrics != nil {
		s.metrics.IncrementActiveSessions(1)
	}
}

// incrementTokenRequests increments the token requests metric if metrics are enabled
func (s *Service) incrementTokenRequests() {
	if s.metrics != nil {
		s.metrics.IncrementTokenRequests()
	}
}

// observeAuthorizeDuration records the duration of an authorization request
func (s *Service) observeAuthorizeDuration(durationMs float64) {
	if s.metrics != nil {
		s.metrics.ObserveAuthorizeDuration(durationMs)
	}
}

// observeTokenExchangeDuration records the duration of a token exchange operation
func (s *Service) observeTokenExchangeDuration(durationMs float64) {
	if s.metrics != nil {
		s.metrics.ObserveTokenExchangeDuration(durationMs)
	}
}

// observeTokenRefreshDuration records the duration of a token refresh operation
func (s *Service) observeTokenRefreshDuration(durationMs float64) {
	if s.metrics != nil {
		s.metrics.ObserveTokenRefreshDuration(durationMs)
	}
}
