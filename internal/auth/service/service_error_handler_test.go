package service

import (
	"context"
	"errors"

	sessionStore "credo/internal/auth/store/session"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/sentinel"

	"go.uber.org/mock/gomock"
)

// AGENTS.MD JUSTIFICATION: Stable error-code mapping across boundary failures
// is validated here because feature tests don't cover internal error translation.
func (s *ServiceSuite) TestHandleTokenError() {
	clientID := "client-123"
	recordID := "record-456"

	assertTokenError := func(name string, err error, flow TokenFlow, expectedCode dErrors.Code, expectedMsg string) {
		s.Run(name, func() {
			ctx := context.Background()
			s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

			result := s.service.handleTokenError(ctx, err, clientID, &recordID, flow)

			s.Require().Error(result)
			s.True(dErrors.HasCode(result, expectedCode))
			s.Contains(result.Error(), expectedMsg)
		})
	}

	assertTokenError("auth code not found", sentinel.ErrNotFound, TokenFlowCode, dErrors.CodeInvalidGrant, "invalid authorization code")
	assertTokenError("auth code expired", sentinel.ErrExpired, TokenFlowCode, dErrors.CodeInvalidGrant, "authorization code expired")
	assertTokenError("auth code already used", sentinel.ErrAlreadyUsed, TokenFlowCode, dErrors.CodeInvalidGrant, "authorization code already used")

	assertTokenError("refresh token not found", sentinel.ErrNotFound, TokenFlowRefresh, dErrors.CodeInvalidGrant, "invalid refresh token")
	assertTokenError("refresh token expired", sentinel.ErrExpired, TokenFlowRefresh, dErrors.CodeInvalidGrant, "refresh token expired")
	assertTokenError("refresh token already used", sentinel.ErrAlreadyUsed, TokenFlowRefresh, dErrors.CodeInvalidGrant, "invalid refresh token")

	assertTokenError("session not found - code flow", sentinel.ErrNotFound, TokenFlowCode, dErrors.CodeInvalidGrant, "invalid authorization code")
	assertTokenError("session not found - refresh flow", sentinel.ErrNotFound, TokenFlowRefresh, dErrors.CodeInvalidGrant, "invalid refresh token")
	assertTokenError("session revoked", sessionStore.ErrSessionRevoked, TokenFlowCode, dErrors.CodeInvalidGrant, "session has been revoked")

	assertTokenError("bad request passthrough", dErrors.New(dErrors.CodeBadRequest, "redirect_uri mismatch"), TokenFlowCode, dErrors.CodeBadRequest, "redirect_uri mismatch")
	// Session validation errors (CodeUnauthorized) are mapped to CodeInvalidGrant per OAuth 2.0 spec
	assertTokenError("session validation failure - maps to invalid_grant", dErrors.New(dErrors.CodeUnauthorized, "session expired"), TokenFlowCode, dErrors.CodeInvalidGrant, "session expired")
	assertTokenError("internal error passthrough", dErrors.New(dErrors.CodeInternal, "db connection failed"), TokenFlowCode, dErrors.CodeInternal, "db connection failed")

	assertTokenError("unknown error", errors.New("random error"), TokenFlowCode, dErrors.CodeInternal, "token handling failed")
}

func (s *ServiceSuite) TestHandleTokenError_AuditAttributes() {
	s.Run("includes record_id when provided", func() {
		ctx := context.Background()
		clientID := "client-123"
		recordID := "record-456"
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		err := s.service.handleTokenError(ctx, sentinel.ErrAlreadyUsed, clientID, &recordID, TokenFlowCode)
		s.Require().Error(err)
	})

	s.Run("excludes record_id when nil", func() {
		ctx := context.Background()
		clientID := "client-123"
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		err := s.service.handleTokenError(ctx, sentinel.ErrAlreadyUsed, clientID, nil, TokenFlowCode)
		s.Require().Error(err)
	})
}
