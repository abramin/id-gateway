package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"credo/internal/auth/models"
	sessionStore "credo/internal/auth/store/session"
	dErrors "credo/pkg/domain-errors"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// TestToken tests the OAuth 2.0 token exchange endpoint (PRD-001 FR-2)
func (s *ServiceSuite) TestToken_Exchange() {
	sessionID := uuid.New()
	userID := uuid.New()
	clientID := "client-123"
	redirectURI := "https://client.app/callback"
	code := "authz_12345"
	issuedAccessToken := "accessToken"
	issuedAccessTokenJTI := "access-token-jti"
	issuedIDToken := "mock-id-token"
	issuedRefreshToken := "ref_mock-refresh-token"

	baseReq := models.TokenRequest{
		GrantType:   GrantTypeAuthorizationCode,
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
		ClientID:       clientID,
		RequestedScope: []string{"openid", "profile"},
		DeviceID:       "device-123",
		Status:         StatusPendingConsent, // Should be pending_consent before token exchange
		CreatedAt:      time.Now().Add(-5 * time.Minute),
		ExpiresAt:      time.Now().Add(24 * time.Hour),
	}

	expectTokens := func(t *testing.T) {
		t.Helper()
		s.mockJWT.EXPECT().GenerateAccessTokenWithJTI(
			userID, sessionID, clientID, []string{"openid", "profile"},
		).Return(issuedAccessToken, issuedAccessTokenJTI, nil)
		s.mockJWT.EXPECT().GenerateIDToken(userID, sessionID, clientID).Return(issuedIDToken, nil)
		s.mockJWT.EXPECT().CreateRefreshToken().Return(issuedRefreshToken, nil)
	}

	expectTokenPersistence := func(t *testing.T, expectedStatus string, sess models.Session, req models.TokenRequest) {
		t.Helper()

		s.mockSessionStore.EXPECT().UpdateSession(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, session *models.Session) error {
				assert.Equal(t, sess.ID, session.ID)
				assert.Equal(t, expectedStatus, session.Status)
				return nil
			},
		)
		s.mockRefreshStore.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, token *models.RefreshTokenRecord) error {
				assert.Equal(t, issuedRefreshToken, token.Token)
				assert.Equal(t, sessionID, token.SessionID)
				assert.False(t, token.Used)
				assert.True(t, token.ExpiresAt.After(time.Now()))
				return nil
			},
		)
		s.mockCodeStore.EXPECT().MarkUsed(gomock.Any(), req.Code).Return(nil)
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)
	}

	s.T().Run("happy path - successful token exchange", func(t *testing.T) {
		req := baseReq
		codeRec := *validCodeRecord
		sess := *validSession
		ctx := context.Background()

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		expectTokens(t)
		expectTokenPersistence(t, StatusActive, sess, req)

		result, err := s.service.Token(ctx, &req)
		require.NoError(s.T(), err)
		assert.Equal(s.T(), issuedAccessToken, result.AccessToken)
		assert.Equal(s.T(), issuedIDToken, result.IDToken)
		assert.Equal(s.T(), issuedRefreshToken, result.RefreshToken)
		assert.Equal(s.T(), "Bearer", result.TokenType)
		assert.Equal(s.T(), s.service.TokenTTL, result.ExpiresIn)
	})

	s.T().Run("session already active - idempotency", func(t *testing.T) {
		req := baseReq
		codeRec := *validCodeRecord
		sess := *validSession
		sess.Status = StatusActive // Already active
		ctx := context.Background()

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		expectTokens(t)
		expectTokenPersistence(t, StatusActive, sess, req)

		result, err := s.service.Token(ctx, &req)
		require.NoError(s.T(), err)
		assert.NotNil(s.T(), result)
		assert.Equal(s.T(), StatusActive, sess.Status) // Should remain active
	})

	// Table test for simple validation errors
	s.T().Run("validation errors", func(t *testing.T) {
		tests := []struct {
			name          string
			modifyReq     func(*models.TokenRequest)
			expectedCode  dErrors.Code
			expectLogAuth bool // Should this increment auth failure metrics?
			expectedMsg   string
		}{
			{
				name: "unsupported grant_type",
				modifyReq: func(r *models.TokenRequest) {
					r.GrantType = "password"
				},
				expectedCode:  dErrors.CodeBadRequest,
				expectLogAuth: false, // Client error, not security failure
				expectedMsg:   "unsupported grant_type",
			},
			{
				name: "authorization_code missing code",
				modifyReq: func(r *models.TokenRequest) {
					r.Code = ""
				},
				expectedCode:  dErrors.CodeValidation,
				expectLogAuth: false,
				expectedMsg:   "code is required",
			},
			{
				name: "authorization_code missing redirect_uri",
				modifyReq: func(r *models.TokenRequest) {
					r.RedirectURI = ""
				},
				expectedCode:  dErrors.CodeValidation,
				expectLogAuth: false,
				expectedMsg:   "redirect_uri is required",
			},
			{
				name: "refresh_token missing refresh_token",
				modifyReq: func(r *models.TokenRequest) {
					r.GrantType = GrantTypeRefreshToken
					r.RefreshToken = ""
					r.Code = ""
					r.RedirectURI = ""
				},
				expectedCode:  dErrors.CodeValidation,
				expectLogAuth: false,
				expectedMsg:   "refresh_token is required",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := baseReq
				tt.modifyReq(&req)

				result, err := s.service.Token(context.Background(), &req)
				assert.Error(t, err)
				assert.Nil(t, result)
				assert.True(t, dErrors.Is(err, tt.expectedCode))
				if tt.expectedMsg != "" {
					assert.Contains(t, err.Error(), tt.expectedMsg)
				}
			})
		}
	})

	// Authorization code validation errors (OAuth 2.0 Section 4.1.3)
	s.T().Run("authorization code not found", func(t *testing.T) {
		req := baseReq

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(nil, sessionStore.ErrNotFound)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeUnauthorized))
		assert.Contains(s.T(), err.Error(), "invalid authorization code")
	})

	s.T().Run("authorization code expired", func(t *testing.T) {
		req := baseReq
		codeRec := *validCodeRecord
		codeRec.ExpiresAt = time.Now().Add(-5 * time.Minute) // Expired

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeUnauthorized))
		assert.Contains(s.T(), err.Error(), "expired")
	})

	s.T().Run("authorization code already used - replay attack", func(t *testing.T) {
		req := baseReq
		codeRec := *validCodeRecord
		codeRec.Used = true

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().RevokeSession(gomock.Any(), sessionID).Return(nil)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeUnauthorized))
		assert.Contains(s.T(), err.Error(), "already used")
	})

	s.T().Run("redirect_uri mismatch", func(t *testing.T) {
		req := baseReq
		req.RedirectURI = "https://evil.com/callback" // Different from code's redirect_uri
		codeRec := *validCodeRecord

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeBadRequest))
		assert.Contains(s.T(), err.Error(), "redirect_uri mismatch")
	})

	// Session validation errors
	s.T().Run("session not found", func(t *testing.T) {
		req := baseReq
		codeRec := *validCodeRecord

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(nil, sessionStore.ErrNotFound)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeUnauthorized))
	})

	s.T().Run("client_id mismatch", func(t *testing.T) {
		req := baseReq
		req.ClientID = "evil-client" // Different from session's client_id
		codeRec := *validCodeRecord
		sess := *validSession

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeBadRequest))
		assert.Contains(s.T(), err.Error(), "client_id mismatch")
	})

	s.T().Run("session revoked", func(t *testing.T) {
		req := baseReq
		codeRec := *validCodeRecord
		sess := *validSession
		sess.Status = "revoked"

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeUnauthorized))
		assert.Contains(s.T(), err.Error(), "revoked")
	})

	s.T().Run("session invalid status", func(t *testing.T) {
		req := baseReq
		codeRec := *validCodeRecord
		sess := *validSession
		sess.Status = "unknown_status"

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeUnauthorized))
		assert.Contains(s.T(), err.Error(), "invalid state")
	})

	s.T().Run("session expired", func(t *testing.T) {
		req := baseReq
		codeRec := *validCodeRecord
		sess := *validSession
		sess.ExpiresAt = time.Now().Add(-1 * time.Hour) // Expired

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeUnauthorized))
		assert.Contains(s.T(), err.Error(), "expired")
	})

	// Infrastructure errors
	s.T().Run("code store lookup error", func(t *testing.T) {
		req := baseReq
		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(nil, errors.New("db error"))

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeInternal))
	})

	s.T().Run("session store lookup error", func(t *testing.T) {
		req := baseReq
		codeRec := *validCodeRecord

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(nil, errors.New("db error"))

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeInternal))
	})

	s.T().Run("mark code used error", func(t *testing.T) {
		req := baseReq
		codeRec := *validCodeRecord
		sess := *validSession

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockJWT.EXPECT().GenerateAccessTokenWithJTI(
			gomock.Any(), gomock.Any(), gomock.Any(), []string{"openid", "profile"},
		).Return(issuedAccessToken, issuedAccessTokenJTI, nil)
		s.mockJWT.EXPECT().GenerateIDToken(gomock.Any(), gomock.Any(), gomock.Any()).Return("mock-id-token", nil)
		s.mockJWT.EXPECT().CreateRefreshToken().Return("ref_mock-refresh-token", nil)
		// Inside RunInTx, MarkUsed fails
		s.mockSessionStore.EXPECT().UpdateSession(gomock.Any(), gomock.Any()).Return(nil)
		s.mockRefreshStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
		s.mockCodeStore.EXPECT().MarkUsed(gomock.Any(), req.Code).Return(errors.New("write error"))

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeInternal))
	})

	s.T().Run("JWT generation errors", func(t *testing.T) {
		tests := []struct {
			name        string
			setupMocks  func(t *testing.T)
			expectedErr string
		}{
			{
				name: "access token generation fails",
				setupMocks: func(t *testing.T) {
					s.mockJWT.EXPECT().GenerateAccessTokenWithJTI(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
						Return("", "", errors.New("jwt error"))
				},
				expectedErr: "failed to generate access token",
			},
			{
				name: "id token generation fails",
				setupMocks: func(t *testing.T) {
					s.mockJWT.EXPECT().GenerateAccessTokenWithJTI(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
						Return("access-token", "access-token-jti", nil)
					s.mockJWT.EXPECT().GenerateIDToken(gomock.Any(), gomock.Any(), gomock.Any()).
						Return("", errors.New("jwt error"))
				},
				expectedErr: "failed to generate ID token",
			},
			{
				name: "refresh token generation fails",
				setupMocks: func(t *testing.T) {
					s.mockJWT.EXPECT().GenerateAccessTokenWithJTI(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
						Return("access-token", "access-token-jti", nil)
					s.mockJWT.EXPECT().GenerateIDToken(gomock.Any(), gomock.Any(), gomock.Any()).
						Return("mock-id", nil)
					s.mockJWT.EXPECT().CreateRefreshToken().
						Return("", errors.New("jwt error"))
				},
				expectedErr: "failed to create refresh token",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := baseReq
				codeRec := *validCodeRecord
				sess := *validSession

				s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
				s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
				tt.setupMocks(t)

				result, err := s.service.Token(context.Background(), &req)
				assert.Error(t, err)
				assert.Nil(t, result)
				assert.True(t, dErrors.Is(err, dErrors.CodeInternal))
				assert.Contains(t, err.Error(), tt.expectedErr)
			})
		}
	})

	s.T().Run("refresh token store error", func(t *testing.T) {
		req := baseReq
		codeRec := *validCodeRecord
		sess := *validSession

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockJWT.EXPECT().GenerateAccessTokenWithJTI(userID, sessionID, clientID, []string{"openid", "profile"}).Return(issuedAccessToken, issuedAccessTokenJTI, nil)
		s.mockJWT.EXPECT().GenerateIDToken(userID, sessionID, clientID).Return("mock-id", nil)
		s.mockJWT.EXPECT().CreateRefreshToken().Return("ref_mock", nil)
		// Inside RunInTx, Create fails
		s.mockSessionStore.EXPECT().UpdateSession(gomock.Any(), gomock.Any()).Return(nil)
		s.mockRefreshStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errors.New("store error"))

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeInternal))
	})
}
