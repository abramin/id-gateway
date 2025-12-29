package service

import (
	"context"
	"errors"

	sessionStore "credo/internal/auth/store/session"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/sentinel"
)

// Token error handling: translates store/sentinel errors into domain errors.

// tokenErrorMapping defines how a sentinel error maps to a domain error.
type tokenErrorMapping struct {
	sentinel   error
	code       dErrors.Code
	codeMsg    string // message for TokenFlowCode (empty = use err.Error())
	refreshMsg string // message for TokenFlowRefresh (empty = use err.Error())
	logReason  string
}

// tokenErrorMappings defines error translations in priority order.
// First match wins; more specific errors should come first.
// Note: Domain-errors from validation are passed through directly (see handleTokenError).
var tokenErrorMappings = []tokenErrorMapping{
	{sentinel.ErrNotFound, dErrors.CodeInvalidGrant, "invalid authorization code", "invalid refresh token", "not_found"},
	{sentinel.ErrExpired, dErrors.CodeInvalidGrant, "authorization code expired", "refresh token expired", "expired"},
	{sentinel.ErrAlreadyUsed, dErrors.CodeInvalidGrant, "authorization code already used", "invalid refresh token", "already_used"},
	{sessionStore.ErrSessionRevoked, dErrors.CodeInvalidGrant, "session has been revoked", "session has been revoked", "session_revoked"},
	{sentinel.ErrInvalidState, dErrors.CodeInvalidGrant, "session not active", "session not active", "invalid_state"},
}

// handleTokenError translates dependency errors into domain errors.
// Uses tokenErrorMappings to determine error code and user-facing message based on flow type.
// Domain errors from session validation (CodeUnauthorized) are mapped to CodeInvalidGrant
// for OAuth 2.0 compliance.
func (s *Service) handleTokenError(ctx context.Context, err error, clientID string, recordID *string, flow TokenFlow) error {
	if err == nil {
		return nil
	}

	attrs := []any{"client_id", clientID}
	if recordID != nil {
		attrs = append(attrs, "record_id", *recordID)
	}

	// Handle domain errors from session validation
	// OAuth 2.0 requires "invalid_grant" for session/token validation failures
	var de *dErrors.Error
	if errors.As(err, &de) {
		if de.Code == dErrors.CodeUnauthorized {
			// Map session validation failures to OAuth invalid_grant
			s.authFailure(ctx, "session_validation_failed", false, attrs...)
			return dErrors.New(dErrors.CodeInvalidGrant, de.Message)
		}
		// Other domain errors pass through unchanged
		s.authFailure(ctx, string(de.Code), false, attrs...)
		return err
	}

	// Handle sentinel.ErrNotFound for session/code lookup failures
	if errors.Is(err, sentinel.ErrNotFound) {
		msg := "invalid authorization code"
		logReason := "not_found"
		if flow == TokenFlowRefresh {
			msg = "invalid refresh token"
		}
		s.authFailure(ctx, logReason, false, attrs...)
		return dErrors.New(dErrors.CodeInvalidGrant, msg)
	}

	// Check remaining mappings in order
	for _, m := range tokenErrorMappings {
		if errors.Is(err, m.sentinel) {
			msg := m.codeMsg
			if flow == TokenFlowRefresh {
				msg = m.refreshMsg
			}
			if msg == "" {
				msg = err.Error()
			}
			s.authFailure(ctx, m.logReason, false, attrs...)
			return dErrors.Wrap(err, m.code, msg)
		}
	}

	// Default: internal error
	s.authFailure(ctx, "internal_error", true, attrs...)
	return dErrors.Wrap(err, dErrors.CodeInternal, "token handling failed")
}
