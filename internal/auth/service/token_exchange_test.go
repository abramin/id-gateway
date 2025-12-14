package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"credo/internal/auth/models"
	tenant "credo/internal/tenant/models"
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
	tenantID := uuid.New()
	clientUUID := uuid.New()
	clientID := "client-123"
	redirectURI := "https://client.app/callback"
	code := "authz_12345"
	issuedAccessToken := "accessToken"
	issuedAccessTokenJTI := "access-token-jti"
	issuedIDToken := "mock-id-token"
	issuedRefreshToken := "ref_mock-refresh-token"

	mockClient := &tenant.Client{
		ID:       clientUUID,
		TenantID: tenantID,
		ClientID: clientID,
		Name:     "Test Client",
		Status:   "active",
	}

	mockTenant := &tenant.Tenant{
		ID:   tenantID,
		Name: "Test Tenant",
	}

	mockUser := &models.User{
		ID:        userID,
		TenantID:  tenantID,
		Email:     "user@test.com",
		FirstName: "Test",
		LastName:  "User",
		Status:    models.UserStatusActive,
	}

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
		Status:         string(models.SessionStatusPendingConsent), // Should be pending_consent before token exchange
		CreatedAt:      time.Now().Add(-5 * time.Minute),
		ExpiresAt:      time.Now().Add(24 * time.Hour),
	}

	expectTokens := func(t *testing.T) {
		t.Helper()
		s.mockJWT.EXPECT().GenerateAccessTokenWithJTI(
			userID, sessionID, clientUUID.String(), tenantID.String(), []string{"openid", "profile"},
		).Return(issuedAccessToken, issuedAccessTokenJTI, nil)
		s.mockJWT.EXPECT().GenerateIDToken(userID, sessionID, clientUUID.String()).Return(issuedIDToken, nil)
		s.mockJWT.EXPECT().CreateRefreshToken().Return(issuedRefreshToken, nil)
	}

	expectTokenPersistence := func(t *testing.T, expectedStatus string, sess models.Session, req models.TokenRequest) {
		t.Helper()

		activate := sess.Status == string(models.SessionStatusPendingConsent)
		s.mockSessionStore.EXPECT().AdvanceLastSeen(gomock.Any(), sess.ID, clientUUID.String(), gomock.Any(), issuedAccessTokenJTI, activate, sess.DeviceID, sess.DeviceFingerprintHash).DoAndReturn(
			func(_ context.Context, id uuid.UUID, client string, seenAt time.Time, jti string, activateFlag bool, deviceID string, fingerprint string) (*models.Session, error) {
				assert.Equal(t, sess.ID, id)
				assert.Equal(t, clientUUID.String(), client)
				assert.Equal(t, issuedAccessTokenJTI, jti)
				assert.Equal(t, activate, activateFlag)
				assert.False(t, seenAt.IsZero())
				sess.Status = expectedStatus
				return &sess, nil
			},
		)
		s.mockRefreshStore.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, token *models.RefreshTokenRecord) error {
				assert.Equal(t, sess.ID, token.SessionID)
				assert.False(t, token.Used)
				assert.True(t, token.ExpiresAt.After(time.Now()))
				return nil
			},
		)
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)
	}

	s.T().Run("happy path - successful token exchange", func(t *testing.T) {
		req := baseReq
		codeRec := *validCodeRecord
		sess := *validSession
		ctx := context.Background()

		// Token exchange now calls resolveTokenContext which needs client, tenant, and user
		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), clientUUID.String()).Return(mockClient, mockTenant, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), userID).Return(mockUser, nil)

		s.mockCodeStore.EXPECT().ConsumeAuthCode(gomock.Any(), req.Code, req.RedirectURI, gomock.Any()).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		expectTokens(t)
		expectTokenPersistence(t, string(models.SessionStatusActive), sess, req)

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
		sess.Status = string(models.SessionStatusActive) // Already active
		ctx := context.Background()

		// Add resolveTokenContext expectations
		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), clientUUID.String()).Return(mockClient, mockTenant, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), userID).Return(mockUser, nil)

		s.mockCodeStore.EXPECT().ConsumeAuthCode(gomock.Any(), req.Code, req.RedirectURI, gomock.Any()).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		expectTokens(t)
		expectTokenPersistence(t, string(models.SessionStatusActive), sess, req)

		result, err := s.service.Token(ctx, &req)
		require.NoError(s.T(), err)
		assert.NotNil(s.T(), result)
		assert.Equal(s.T(), string(models.SessionStatusActive), sess.Status) // Should remain active
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
					r.GrantType = string(models.GrantRefreshToken)
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

	// Infrastructure errors - verify error propagation through handleTokenError
	s.T().Run("code store lookup error", func(t *testing.T) {
		req := baseReq
		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(nil, errors.New("db error"))

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
					s.mockJWT.EXPECT().GenerateAccessTokenWithJTI(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
						Return("", "", errors.New("jwt error"))
				},
				expectedErr: "failed to generate tokens",
			},
			{
				name: "id token generation fails",
				setupMocks: func(t *testing.T) {
					s.mockJWT.EXPECT().GenerateAccessTokenWithJTI(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
						Return("access-token", "access-token-jti", nil)
					s.mockJWT.EXPECT().GenerateIDToken(gomock.Any(), gomock.Any(), gomock.Any()).
						Return("", errors.New("jwt error"))
				},
				expectedErr: "failed to generate tokens",
			},
			{
				name: "refresh token generation fails",
				setupMocks: func(t *testing.T) {
					s.mockJWT.EXPECT().GenerateAccessTokenWithJTI(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
						Return("access-token", "access-token-jti", nil)
					s.mockJWT.EXPECT().GenerateIDToken(gomock.Any(), gomock.Any(), gomock.Any()).
						Return("mock-id", nil)
					s.mockJWT.EXPECT().CreateRefreshToken().
						Return("", errors.New("jwt error"))
				},
				expectedErr: "failed to generate tokens",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := baseReq
				codeRec := *validCodeRecord
				sess := *validSession

				// resolveTokenContext mocks
				s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
				s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
				s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), clientUUID.String()).Return(mockClient, mockTenant, nil)
				s.mockUserStore.EXPECT().FindByID(gomock.Any(), userID).Return(mockUser, nil)

				// Transaction mocks
				s.mockCodeStore.EXPECT().ConsumeAuthCode(gomock.Any(), req.Code, req.RedirectURI, gomock.Any()).Return(&codeRec, nil)
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
}
