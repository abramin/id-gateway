package service

import (
	"context"
	"errors"
	"time"

	"credo/internal/auth/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"

	"github.com/google/uuid"
	"go.uber.org/mock/gomock"
)

// TestTokenExchangeFlow tests the OAuth 2.0 token exchange endpoint (PRD-001 FR-2)
//
// AGENTS.MD JUSTIFICATION (per testing.md doctrine):
// These unit tests verify behaviors NOT covered by Gherkin:
// - validation errors: Tests input validation error codes (fast feedback)
// - infrastructure errors: Tests error mapping from store failures → domain errors
// - JWT generation errors: Tests error propagation from token generation
// RFC 6749 §5.2 invalid_grant scenarios are covered by e2e feature tests
// (auth_normal_flow.feature, auth_token_lifecycle.feature).
func (s *ServiceSuite) TestTokenExchangeFlow_ValidationAndErrorMapping() {
	sessionID := id.SessionID(uuid.New())
	userID := id.UserID(uuid.New())
	tenantID := id.TenantID(uuid.New())
	clientUUID := id.ClientID(uuid.New())
	clientID := "client-123"
	redirectURI := "https://client.app/callback"
	code := "authz_12345"

	mockClient, mockTenant := s.newTestClient(tenantID, clientUUID)
	mockUser := s.newTestUser(userID, tenantID)

	baseReq := models.TokenRequest{
		GrantType:   string(models.GrantAuthorizationCode),
		Code:        code,
		RedirectURI: redirectURI,
		ClientID:    clientID,
	}

	validCodeRecord := &models.AuthorizationCodeRecord{
		Code:        code,
		SessionID:   sessionID,
		RedirectURI: redirectURI,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		Used:        false,
		CreatedAt:   time.Now().Add(-1 * time.Minute),
	}

	validSession := &models.Session{
		ID:             sessionID,
		UserID:         userID,
		ClientID:       clientUUID,
		TenantID:       tenantID,
		RequestedScope: []string{"openid", "profile"},
		DeviceID:       "device-123",
		Status:         models.SessionStatusPendingConsent, // Should be pending_consent before token exchange
		CreatedAt:      time.Now().Add(-5 * time.Minute),
		ExpiresAt:      time.Now().Add(24 * time.Hour),
	}

	s.Run("validation: unsupported grant_type", func() {
		req := baseReq
		req.GrantType = "password"

		result, err := s.service.Token(context.Background(), &req)
		s.Require().Error(err)
		s.Nil(result)
		s.True(dErrors.HasCode(err, dErrors.CodeBadRequest))
		s.Contains(err.Error(), "unsupported grant_type")
	})

	s.Run("validation: authorization_code missing code", func() {
		req := baseReq
		req.Code = ""

		result, err := s.service.Token(context.Background(), &req)
		s.Require().Error(err)
		s.Nil(result)
		s.True(dErrors.HasCode(err, dErrors.CodeValidation))
		s.Contains(err.Error(), "code is required")
	})

	s.Run("validation: authorization_code missing redirect_uri", func() {
		req := baseReq
		req.RedirectURI = ""

		result, err := s.service.Token(context.Background(), &req)
		s.Require().Error(err)
		s.Nil(result)
		s.True(dErrors.HasCode(err, dErrors.CodeValidation))
		s.Contains(err.Error(), "redirect_uri is required")
	})

	s.Run("validation: refresh_token missing refresh_token", func() {
		req := baseReq
		req.GrantType = string(models.GrantRefreshToken)
		req.RefreshToken = ""
		req.Code = ""
		req.RedirectURI = ""

		result, err := s.service.Token(context.Background(), &req)
		s.Require().Error(err)
		s.Nil(result)
		s.True(dErrors.HasCode(err, dErrors.CodeValidation))
		s.Contains(err.Error(), "refresh_token is required")
	})

	// Infrastructure errors - verify error propagation through handleTokenError
	// NOTE: RFC 6749 §5.2 invalid_grant scenarios (code not found, expired, used, redirect_uri mismatch)
	// are covered by e2e/features/auth_normal_flow.feature and auth_token_lifecycle.feature
	s.Run("code store lookup error", func() {
		req := baseReq
		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(nil, errors.New("db error"))
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		result, err := s.service.Token(context.Background(), &req)
		s.Require().Error(err)
		s.Nil(result)
		s.True(dErrors.HasCode(err, dErrors.CodeInternal))
	})

	setupPreTx := func(req models.TokenRequest, codeRec models.AuthorizationCodeRecord, sess models.Session) {
		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), clientID).Return(mockClient, mockTenant, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), userID).Return(mockUser, nil)
	}

	s.Run("JWT generation error: access token generation fails", func() {
		req := baseReq
		codeRec := *validCodeRecord
		sess := *validSession
		setupPreTx(req, codeRec, sess)

		s.mockJWT.EXPECT().GenerateAccessTokenWithJTI(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return("", "", errors.New("jwt error"))

		result, err := s.service.Token(context.Background(), &req)
		s.Require().Error(err)
		s.Nil(result)
		s.True(dErrors.HasCode(err, dErrors.CodeInternal))
		s.Contains(err.Error(), "failed to generate tokens")
	})

	s.Run("JWT generation error: id token generation fails", func() {
		req := baseReq
		codeRec := *validCodeRecord
		sess := *validSession
		setupPreTx(req, codeRec, sess)

		s.mockJWT.EXPECT().GenerateAccessTokenWithJTI(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return("access-token", "access-token-jti", nil)
		s.mockJWT.EXPECT().GenerateIDToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return("", errors.New("jwt error"))

		result, err := s.service.Token(context.Background(), &req)
		s.Require().Error(err)
		s.Nil(result)
		s.True(dErrors.HasCode(err, dErrors.CodeInternal))
		s.Contains(err.Error(), "failed to generate tokens")
	})

	s.Run("JWT generation error: refresh token generation fails", func() {
		req := baseReq
		codeRec := *validCodeRecord
		sess := *validSession
		setupPreTx(req, codeRec, sess)

		s.mockJWT.EXPECT().GenerateAccessTokenWithJTI(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return("access-token", "access-token-jti", nil)
		s.mockJWT.EXPECT().GenerateIDToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return("mock-id", nil)
		s.mockJWT.EXPECT().CreateRefreshToken().
			Return("", errors.New("jwt error"))

		result, err := s.service.Token(context.Background(), &req)
		s.Require().Error(err)
		s.Nil(result)
		s.True(dErrors.HasCode(err, dErrors.CodeInternal))
		s.Contains(err.Error(), "failed to generate tokens")
	})
}
