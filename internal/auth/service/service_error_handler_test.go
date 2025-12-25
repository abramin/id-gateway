package service

import (
	"context"
	"errors"
	"testing"

	authCodeStore "credo/internal/auth/store/authorization-code"
	refreshTokenStore "credo/internal/auth/store/refresh-token"
	sessionStore "credo/internal/auth/store/session"
	dErrors "credo/pkg/domain-errors"
)

func (s *ServiceSuite) TestHandleTokenError() {
	clientID := "client-123"
	recordID := "record-456"

	tests := []struct {
		name           string
		err            error
		flow           TokenFlow
		expectedCode   dErrors.Code
		expectedMsg    string
		auditReason    string
		expectRecordID bool
	}{
		{
			name:           "auth code not found",
			err:            authCodeStore.ErrNotFound,
			flow:           TokenFlowCode,
			expectedCode:   dErrors.CodeInvalidGrant,
			expectedMsg:    "invalid authorization code",
			auditReason:    "code_not_found",
			expectRecordID: false,
		},
		{
			name:           "auth code expired",
			err:            authCodeStore.ErrAuthCodeExpired,
			flow:           TokenFlowCode,
			expectedCode:   dErrors.CodeInvalidGrant,
			expectedMsg:    "authorization code expired",
			auditReason:    "authorization_code_expired",
			expectRecordID: false,
		},
		{
			name:           "auth code already used",
			err:            authCodeStore.ErrAuthCodeUsed,
			flow:           TokenFlowCode,
			expectedCode:   dErrors.CodeInvalidGrant,
			expectedMsg:    "authorization code already used",
			auditReason:    "authorization_code_reused",
			expectRecordID: true,
		},
		// Refresh token errors
		{
			name:           "refresh token not found",
			err:            refreshTokenStore.ErrNotFound,
			flow:           TokenFlowRefresh,
			expectedCode:   dErrors.CodeInvalidGrant,
			expectedMsg:    "invalid refresh token",
			auditReason:    "refresh_token_not_found",
			expectRecordID: false,
		},
		{
			name:           "refresh token expired",
			err:            refreshTokenStore.ErrRefreshTokenExpired,
			flow:           TokenFlowRefresh,
			expectedCode:   dErrors.CodeInvalidGrant,
			expectedMsg:    "refresh token expired",
			auditReason:    "refresh_token_expired",
			expectRecordID: true,
		},
		{
			name:           "refresh token already used",
			err:            refreshTokenStore.ErrRefreshTokenUsed,
			flow:           TokenFlowRefresh,
			expectedCode:   dErrors.CodeInvalidGrant,
			expectedMsg:    "invalid refresh token",
			auditReason:    "refresh_token_reused",
			expectRecordID: true,
		},
		// Session errors - context-aware (code flow)
		{
			name:           "session not found - code flow",
			err:            sessionStore.ErrNotFound,
			flow:           TokenFlowCode,
			expectedCode:   dErrors.CodeInvalidGrant,
			expectedMsg:    "invalid authorization code",
			auditReason:    "session_not_found",
			expectRecordID: true,
		},
		{
			name:           "session not found - refresh flow",
			err:            sessionStore.ErrNotFound,
			flow:           TokenFlowRefresh,
			expectedCode:   dErrors.CodeInvalidGrant,
			expectedMsg:    "invalid refresh token",
			auditReason:    "session_not_found",
			expectRecordID: true,
		},
		{
			name:           "session revoked",
			err:            sessionStore.ErrSessionRevoked,
			flow:           TokenFlowCode,
			expectedCode:   dErrors.CodeInvalidGrant,
			expectedMsg:    "session has been revoked",
			auditReason:    "session_revoked",
			expectRecordID: true,
		},
		// Domain errors passthrough
		{
			name:           "bad request passthrough",
			err:            dErrors.New(dErrors.CodeBadRequest, "redirect_uri mismatch"),
			flow:           TokenFlowCode,
			expectedCode:   dErrors.CodeBadRequest,
			expectedMsg:    "redirect_uri mismatch",
			auditReason:    "bad_request",
			expectRecordID: false,
		},
		{
			name:           "unauthorized - invalid session state",
			err:            dErrors.New(dErrors.CodeUnauthorized, "session expired"),
			flow:           TokenFlowCode,
			expectedCode:   dErrors.CodeUnauthorized,
			expectedMsg:    "session expired",
			auditReason:    "invalid_session_state",
			expectRecordID: true,
		},
		{
			name:           "internal error passthrough",
			err:            dErrors.New(dErrors.CodeInternal, "db connection failed"),
			flow:           TokenFlowCode,
			expectedCode:   dErrors.CodeInternal,
			expectedMsg:    "db connection failed",
			auditReason:    "", // No audit for passthrough
			expectRecordID: false,
		},
		// Unknown errors
		{
			name:           "unknown error",
			err:            errors.New("random error"),
			flow:           TokenFlowCode,
			expectedCode:   dErrors.CodeInternal,
			expectedMsg:    "token handling failed",
			auditReason:    "internal_error",
			expectRecordID: false,
		},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			result := s.service.handleTokenError(ctx, tt.err, clientID, &recordID, tt.flow)

			s.Error(result)
			s.True(dErrors.HasCode(result, tt.expectedCode))
			s.Contains(result.Error(), tt.expectedMsg)
		})
	}
}

func (s *ServiceSuite) TestHandleTokenError_AuditAttributes() {
	s.T().Run("includes record_id when provided", func(t *testing.T) {
		ctx := context.Background()
		clientID := "client-123"
		recordID := "record-456"

		err := s.service.handleTokenError(ctx, authCodeStore.ErrAuthCodeUsed, clientID, &recordID, TokenFlowCode)
		s.Error(err)
	})

	s.T().Run("excludes record_id when nil", func(t *testing.T) {
		ctx := context.Background()
		clientID := "client-123"

		err := s.service.handleTokenError(ctx, authCodeStore.ErrAuthCodeUsed, clientID, nil, TokenFlowCode)
		s.Error(err)
	})
}
