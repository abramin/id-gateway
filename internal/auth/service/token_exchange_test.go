package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"credo/internal/auth/models"
	dErrors "credo/pkg/domain-errors"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// TestToken_Exchange tests the OAuth 2.0 token exchange endpoint (PRD-001 FR-2)
//
// AGENTS.MD JUSTIFICATION (per testing.md doctrine):
// These unit tests verify behaviors NOT covered by Gherkin:
// - validation errors: Tests input validation error codes (fast feedback)
// - infrastructure errors: Tests error mapping from store failures → domain errors
// - JWT generation errors: Tests error propagation from token generation
//
// REMOVED per testing.md (duplicate of e2e/features/auth_normal_flow.feature):
// - "happy path - successful token exchange" - covered by "Complete OAuth2 authorization code flow"
// - "session already active - idempotency" - covered by auth flow tests
//
// RFC 6749 §5.2 invalid_grant scenarios are covered by e2e feature tests
// (auth_normal_flow.feature, auth_token_lifecycle.feature).
func (s *ServiceSuite) TestToken_Exchange() {
	sessionID := uuid.New()
	userID := uuid.New()
	tenantID := uuid.New()
	clientUUID := uuid.New()
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
		Status:         string(models.SessionStatusPendingConsent), // Should be pending_consent before token exchange
		CreatedAt:      time.Now().Add(-5 * time.Minute),
		ExpiresAt:      time.Now().Add(24 * time.Hour),
	}

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
			s.T().Run(tt.name, func(t *testing.T) {
				req := baseReq
				tt.modifyReq(&req)

				result, err := s.service.Token(context.Background(), &req)
				assert.Error(s.T(), err)
				assert.Nil(s.T(), result)
				assert.True(s.T(), dErrors.HasCode(err, tt.expectedCode))
				if tt.expectedMsg != "" {
					assert.Contains(s.T(), err.Error(), tt.expectedMsg)
				}
			})
		}
	})

	// Infrastructure errors - verify error propagation through handleTokenError
	// NOTE: RFC 6749 §5.2 invalid_grant scenarios (code not found, expired, used, redirect_uri mismatch)
	// are covered by e2e/features/auth_normal_flow.feature and auth_token_lifecycle.feature
	s.T().Run("code store lookup error", func(t *testing.T) {
		req := baseReq
		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(nil, errors.New("db error"))

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.HasCode(err, dErrors.CodeInternal))
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
					s.mockJWT.EXPECT().GenerateIDToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
						Return("", errors.New("jwt error"))
				},
				expectedErr: "failed to generate tokens",
			},
			{
				name: "refresh token generation fails",
				setupMocks: func(t *testing.T) {
					s.mockJWT.EXPECT().GenerateAccessTokenWithJTI(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
						Return("access-token", "access-token-jti", nil)
					s.mockJWT.EXPECT().GenerateIDToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
						Return("mock-id", nil)
					s.mockJWT.EXPECT().CreateRefreshToken().
						Return("", errors.New("jwt error"))
				},
				expectedErr: "failed to generate tokens",
			},
		}

		for _, tt := range tests {
			s.T().Run(tt.name, func(t *testing.T) {
				req := baseReq
				codeRec := *validCodeRecord
				sess := *validSession

				// resolveTokenContext mocks
				s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
				s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
				s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), clientID).Return(mockClient, mockTenant, nil)
				s.mockUserStore.EXPECT().FindByID(gomock.Any(), userID).Return(mockUser, nil)

				// Transaction mocks
				s.mockCodeStore.EXPECT().ConsumeAuthCode(gomock.Any(), req.Code, req.RedirectURI, gomock.Any()).Return(&codeRec, nil)
				s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
				tt.setupMocks(s.T())

				result, err := s.service.Token(context.Background(), &req)
				assert.Error(s.T(), err)
				assert.Nil(s.T(), result)
				assert.True(s.T(), dErrors.HasCode(err, dErrors.CodeInternal))
				assert.Contains(s.T(), err.Error(), tt.expectedErr)
			})
		}
	})
}
