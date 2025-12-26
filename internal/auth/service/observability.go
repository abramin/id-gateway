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

func (s *Service) authFailure(ctx context.Context, reason string, isError bool, attributes ...any) {
	s.logAuthFailure(ctx, reason, isError, attributes...)
	if s.metrics != nil {
		s.metrics.IncrementAuthFailures()
	}
}

func (s *Service) logAuthFailure(ctx context.Context, reason string, isError bool, attributes ...any) {
	// Add request_id from context if available
	if requestID := request.GetRequestID(ctx); requestID != "" {
		attributes = append(attributes, "request_id", requestID)
	}
	args := append(attributes, "event", audit.EventAuthFailed, "reason", reason, "log_type", "standard")
	if s.logger == nil {
		return
	}
	if isError {
		s.logger.ErrorContext(ctx, string(audit.EventAuthFailed), args...)
		return
	}
	s.logger.WarnContext(ctx, string(audit.EventAuthFailed), args...)
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
