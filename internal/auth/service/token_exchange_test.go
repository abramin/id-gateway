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

	// expectTokenPersistence sets up mock expectations for session advancement and refresh token creation.
	// accessTokenJTI must match what expectTokenGeneration returns.
	expectTokenPersistence := func(expectedStatus string, sess models.Session, accessTokenJTI string) {
		activate := sess.Status == string(models.SessionStatusPendingConsent)
		s.mockSessionStore.EXPECT().AdvanceLastSeen(gomock.Any(), sess.ID, clientUUID.String(), gomock.Any(), accessTokenJTI, activate, sess.DeviceID, sess.DeviceFingerprintHash).DoAndReturn(
			func(_ context.Context, id uuid.UUID, client string, seenAt time.Time, jti string, activateFlag bool, deviceID string, fingerprint string) (*models.Session, error) {
				assert.Equal(s.T(), sess.ID, id)
				assert.Equal(s.T(), clientUUID.String(), client)
				assert.Equal(s.T(), accessTokenJTI, jti)
				assert.Equal(s.T(), activate, activateFlag)
				assert.False(s.T(), seenAt.IsZero())
				sess.Status = expectedStatus
				return &sess, nil
			},
		)
		s.mockRefreshStore.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, token *models.RefreshTokenRecord) error {
				assert.Equal(s.T(), sess.ID, token.SessionID)
				assert.False(s.T(), token.Used)
				assert.True(s.T(), token.ExpiresAt.After(time.Now()))
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
		accessToken, accessTokenJTI, idToken, refreshToken := s.expectTokenGeneration(userID, sessionID, clientUUID, tenantID, sess.RequestedScope)
		expectTokenPersistence(string(models.SessionStatusActive), sess, accessTokenJTI)

		result, err := s.service.Token(ctx, &req)
		require.NoError(s.T(), err)
		assert.Equal(s.T(), accessToken, result.AccessToken)
		assert.Equal(s.T(), idToken, result.IDToken)
		assert.Equal(s.T(), refreshToken, result.RefreshToken)
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
		_, accessTokenJTI, _, _ := s.expectTokenGeneration(userID, sessionID, clientUUID, tenantID, sess.RequestedScope)
		expectTokenPersistence(string(models.SessionStatusActive), sess, accessTokenJTI)

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
			s.T().Run(tt.name, func(t *testing.T) {
				req := baseReq
				tt.modifyReq(&req)

				result, err := s.service.Token(context.Background(), &req)
				assert.Error(s.T(), err)
				assert.Nil(s.T(), result)
				assert.True(s.T(), dErrors.Is(err, tt.expectedCode))
				if tt.expectedMsg != "" {
					assert.Contains(s.T(), err.Error(), tt.expectedMsg)
				}
			})
		}
	})

	// RFC 6749 §5.2: invalid_grant errors - code not found, expired, or used
	s.T().Run("invalid_grant scenarios (RFC 6749 §5.2)", func(t *testing.T) {
		tests := []struct {
			name         string
			setupMocks   func()
			expectedCode dErrors.Code
			expectedMsg  string
		}{
			{
				name: "authorization code not found",
				setupMocks: func() {
					s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), code).Return(nil, dErrors.New(dErrors.CodeNotFound, "code not found"))
				},
				expectedCode: dErrors.CodeInvalidGrant,
				expectedMsg:  "invalid authorization code",
			},
			{
				name: "authorization code expired",
				setupMocks: func() {
					expiredCode := &models.AuthorizationCodeRecord{
						Code:        code,
						SessionID:   sessionID,
						RedirectURI: redirectURI,
						ExpiresAt:   time.Now().Add(-5 * time.Minute), // Expired 5 minutes ago
						Used:        false,
						CreatedAt:   time.Now().Add(-15 * time.Minute),
					}
					s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), code).Return(expiredCode, nil)
				},
				expectedCode: dErrors.CodeInvalidGrant,
				expectedMsg:  "authorization code expired",
			},
			{
				name: "authorization code already used",
				setupMocks: func() {
					usedCode := &models.AuthorizationCodeRecord{
						Code:        code,
						SessionID:   sessionID,
						RedirectURI: redirectURI,
						ExpiresAt:   time.Now().Add(5 * time.Minute),
						Used:        true, // Already used
						CreatedAt:   time.Now().Add(-1 * time.Minute),
					}
					s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), code).Return(usedCode, nil)
				},
				expectedCode: dErrors.CodeInvalidGrant,
				expectedMsg:  "authorization code already used",
			},
			{
				name: "redirect_uri mismatch",
				setupMocks: func() {
					// Code was issued for a different redirect_uri
					codeWithDifferentRedirect := &models.AuthorizationCodeRecord{
						Code:        code,
						SessionID:   sessionID,
						RedirectURI: "https://original.app/callback", // Different from request
						ExpiresAt:   time.Now().Add(5 * time.Minute),
						Used:        false,
						CreatedAt:   time.Now().Add(-1 * time.Minute),
					}
					s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), code).Return(codeWithDifferentRedirect, nil)
				},
				expectedCode: dErrors.CodeInvalidGrant,
				expectedMsg:  "redirect_uri mismatch",
			},
		}

		for _, tt := range tests {
			s.T().Run(tt.name, func(t *testing.T) {
				req := baseReq
				tt.setupMocks()

				result, err := s.service.Token(context.Background(), &req)
				assert.Error(t, err)
				assert.Nil(t, result)
				assert.True(t, dErrors.Is(err, tt.expectedCode),
					"expected %s but got %v", tt.expectedCode, err)
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
				s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), clientUUID.String()).Return(mockClient, mockTenant, nil)
				s.mockUserStore.EXPECT().FindByID(gomock.Any(), userID).Return(mockUser, nil)

				// Transaction mocks
				s.mockCodeStore.EXPECT().ConsumeAuthCode(gomock.Any(), req.Code, req.RedirectURI, gomock.Any()).Return(&codeRec, nil)
				s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
				tt.setupMocks(s.T())

				result, err := s.service.Token(context.Background(), &req)
				assert.Error(s.T(), err)
				assert.Nil(s.T(), result)
				assert.True(s.T(), dErrors.Is(err, dErrors.CodeInternal))
				assert.Contains(s.T(), err.Error(), tt.expectedErr)
			})
		}
	})
}

// TestToken_ClientSecretValidation tests that token endpoint validates client_secret
// for confidential clients (PRD-026A FR-6).
// This test is expected to FAIL until the validation is implemented.
//
// Prerequisites that also need to be implemented:
// 1. TokenRequest needs a ClientSecret field
// 2. Client model needs an IsPublic field to distinguish public vs confidential
// 3. Token endpoint needs to validate secret against client.ClientSecretHash
func (s *ServiceSuite) TestToken_ClientSecretValidation() {
	sessionID := uuid.New()
	userID := uuid.New()
	tenantID := uuid.New()
	clientUUID := uuid.New()
	code := "authz_12345"
	redirectURI := "https://client.app/callback"

	// Confidential client with a secret hash
	// In reality, this would be a bcrypt/argon2 hash of "correct-secret"
	// GAP: Client model needs IsPublic field to distinguish public vs confidential
	confidentialClient := &tenant.Client{
		ID:               clientUUID,
		TenantID:         tenantID,
		ClientID:         "confidential-client",
		Name:             "Confidential App",
		Status:           "active",
		ClientSecretHash: "$argon2id$v=19$m=65536,t=1,p=4$somesalt$somehash", // Hash of "correct-secret"
		RedirectURIs:     []string{redirectURI},
		AllowedGrants:    []string{"authorization_code", "refresh_token"},
		AllowedScopes:    []string{"openid", "profile"},
		// IsPublic: false, // GAP: This field doesn't exist yet on Client model!
	}

	// Public client without a secret (no ClientSecretHash)
	// GAP: Currently we infer public from empty ClientSecretHash, but should be explicit
	publicClient := &tenant.Client{
		ID:            clientUUID,
		TenantID:      tenantID,
		ClientID:      "public-client",
		Name:          "Public SPA",
		Status:        "active",
		RedirectURIs:  []string{redirectURI},
		AllowedGrants: []string{"authorization_code", "refresh_token"},
		AllowedScopes: []string{"openid", "profile"},
		// IsPublic: true, // GAP: This field doesn't exist yet on Client model!
		// ClientSecretHash is empty - currently the only way to identify public clients
	}

	mockTenant := &tenant.Tenant{
		ID:     tenantID,
		Name:   "Test Tenant",
		Status: "active",
	}

	mockUser := s.newTestUser(userID, tenantID)

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
		Status:         string(models.SessionStatusPendingConsent),
		CreatedAt:      time.Now().Add(-5 * time.Minute),
		ExpiresAt:      time.Now().Add(24 * time.Hour),
	}

	s.T().Run("confidential client without secret rejected", func(t *testing.T) {
		// NOTE: TokenRequest.ClientSecret field doesn't exist yet!
		req := models.TokenRequest{
			GrantType:   string(models.GrantAuthorizationCode),
			Code:        code,
			RedirectURI: redirectURI,
			ClientID:    "confidential-client",
			// ClientSecret: "", // Missing - should fail for confidential client
		}
		ctx := context.Background()

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(validCodeRecord, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(validSession, nil)
		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), clientUUID.String()).Return(confidentialClient, mockTenant, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), userID).Return(mockUser, nil)

		result, err := s.service.Token(ctx, &req)

		// This test documents the expected behavior per PRD-026A FR-6:
		// "/oauth/token validates client_id/secret (if confidential)"
		assert.Error(t, err, "expected error when confidential client provides no secret")
		assert.Nil(t, result)
		assert.True(t, dErrors.Is(err, dErrors.CodeUnauthorized),
			"expected unauthorized error code for missing client_secret")
		assert.Contains(t, err.Error(), "client_secret", "error message should mention client_secret")
	})

	s.T().Run("confidential client with wrong secret rejected", func(t *testing.T) {
		// NOTE: TokenRequest.ClientSecret field doesn't exist yet!
		req := models.TokenRequest{
			GrantType:   string(models.GrantAuthorizationCode),
			Code:        code,
			RedirectURI: redirectURI,
			ClientID:    "confidential-client",
			// ClientSecret: "wrong-secret", // Wrong secret - should fail
		}
		ctx := context.Background()

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(validCodeRecord, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(validSession, nil)
		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), clientUUID.String()).Return(confidentialClient, mockTenant, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), userID).Return(mockUser, nil)

		result, err := s.service.Token(ctx, &req)

		assert.Error(t, err, "expected error when confidential client provides wrong secret")
		assert.Nil(t, result)
		assert.True(t, dErrors.Is(err, dErrors.CodeUnauthorized),
			"expected unauthorized error code for invalid client_secret")
	})

	s.T().Run("public client without secret accepted", func(t *testing.T) {
		req := models.TokenRequest{
			GrantType:   string(models.GrantAuthorizationCode),
			Code:        code,
			RedirectURI: redirectURI,
			ClientID:    "public-client",
			// No ClientSecret - OK for public client
		}
		ctx := context.Background()

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(validCodeRecord, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(validSession, nil)
		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), clientUUID.String()).Return(publicClient, mockTenant, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), userID).Return(mockUser, nil)

		s.mockCodeStore.EXPECT().ConsumeAuthCode(gomock.Any(), req.Code, req.RedirectURI, gomock.Any()).Return(validCodeRecord, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(validSession, nil)
		_, accessTokenJTI, _, _ := s.expectTokenGeneration(userID, sessionID, clientUUID, tenantID, validSession.RequestedScope)
		s.mockSessionStore.EXPECT().AdvanceLastSeen(gomock.Any(), validSession.ID, clientUUID.String(), gomock.Any(), accessTokenJTI, true, validSession.DeviceID, validSession.DeviceFingerprintHash).
			Return(validSession, nil)
		s.mockRefreshStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		result, err := s.service.Token(ctx, &req)
		assert.NoError(t, err, "expected success for public client without secret")
		assert.NotNil(t, result)
	})
}
