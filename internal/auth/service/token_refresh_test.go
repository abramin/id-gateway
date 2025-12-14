package service

import (
	"context"
	"testing"
	"time"

	"credo/internal/auth/device"
	"credo/internal/auth/models"
	refreshTokenStore "credo/internal/auth/store/refresh-token"
	sessionStore "credo/internal/auth/store/session"
	"credo/internal/platform/middleware"
	tenant "credo/internal/tenant/models"
	dErrors "credo/pkg/domain-errors"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func (s *ServiceSuite) TestToken_RefreshToken() {
	sessionID := uuid.New()
	userID := uuid.New()
	clientUUID := uuid.New()
	tenantID := uuid.New()
	clientID := "client-123"
	refreshTokenString := "ref_abc123xyz"
	issuedAccessToken := "new-access-token"
	issuedAccessTokenJTI := "new-access-token-jti"
	issuedIDToken := "new-id-token"
	issuedRefreshToken := "ref_new_token"

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
		Verified:  false,
		Status:    models.UserStatusActive,
	}

	newReq := func() models.TokenRequest {
		return models.TokenRequest{
			GrantType:    string(models.GrantRefreshToken),
			RefreshToken: refreshTokenString,
			ClientID:     clientID,
		}
	}

	validRefreshToken := &models.RefreshTokenRecord{
		Token:           refreshTokenString,
		SessionID:       sessionID,
		CreatedAt:       time.Now().Add(-1 * time.Hour),
		LastRefreshedAt: nil,
		ExpiresAt:       time.Now().Add(29 * 24 * time.Hour), // 29 days remaining
		Used:            false,
	}

	validSession := &models.Session{
		ID:             sessionID,
		UserID:         userID,
		ClientID:       clientUUID,
		TenantID:       tenantID,
		RequestedScope: []string{"openid", "profile"},
		DeviceID:       "device-123",
		Status:         string(models.SessionStatusActive),
		CreatedAt:      time.Now().Add(-1 * time.Hour),
		ExpiresAt:      time.Now().Add(23 * time.Hour),
	}

	expectTokens := func(t *testing.T) {
		t.Helper()
		s.mockJWT.EXPECT().GenerateAccessTokenWithJTI(
			userID, sessionID, clientUUID.String(), validSession.TenantID.String(), []string{"openid", "profile"},
		).Return(issuedAccessToken, issuedAccessTokenJTI, nil)
		s.mockJWT.EXPECT().GenerateIDToken(userID, sessionID, clientUUID.String()).Return(issuedIDToken, nil)
		s.mockJWT.EXPECT().CreateRefreshToken().Return(issuedRefreshToken, nil)
	}

	s.T().Run("happy path - successful token refresh", func(t *testing.T) {
		req := newReq()
		refreshRec := *validRefreshToken
		sess := *validSession
		ctx := context.Background()

		// Expected flow (updated for PRD-026A FR-4.5.4 validation before transaction):
		// 1. Find refresh token (non-transactional, for validation)
		s.mockRefreshStore.EXPECT().Find(gomock.Any(), refreshTokenString).Return(&refreshRec, nil)
		// 2. Find session (non-transactional, for validation)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		// 3. Validate client and user status (PRD-026A FR-4.5.4)
		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), clientUUID.String()).Return(mockClient, mockTenant, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), userID).Return(mockUser, nil)
		// 4. Inside transaction: consume refresh token, re-find session, generate tokens
		s.mockRefreshStore.EXPECT().ConsumeRefreshToken(gomock.Any(), refreshTokenString, gomock.Any()).Return(&refreshRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		expectTokens(t)
		// Inside RunInTx: Advance session, create new token
		s.mockSessionStore.EXPECT().AdvanceLastRefreshed(gomock.Any(), sess.ID, req.ClientID, gomock.Any(), issuedAccessTokenJTI, sess.DeviceID, sess.DeviceFingerprintHash).DoAndReturn(
			func(ctx context.Context, sessionID uuid.UUID, clientID string, ts time.Time, jti string, deviceID string, fingerprint string) (*models.Session, error) {
				assert.Equal(s.T(), sess.ID, sessionID)
				assert.False(s.T(), ts.IsZero())
				assert.Equal(s.T(), issuedAccessTokenJTI, jti)
				return &sess, nil
			})
		s.mockRefreshStore.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, token *models.RefreshTokenRecord) error {
				assert.Equal(s.T(), issuedRefreshToken, token.Token)
				assert.Equal(s.T(), sessionID, token.SessionID)
				assert.False(s.T(), token.Used)
				return nil
			})
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		result, err := s.service.Token(ctx, &req)
		require.NoError(s.T(), err)
		assert.Equal(s.T(), issuedAccessToken, result.AccessToken)
		assert.Equal(s.T(), issuedIDToken, result.IDToken)
		assert.Equal(s.T(), issuedRefreshToken, result.RefreshToken)
		assert.Equal(s.T(), "Bearer", result.TokenType)
		assert.Equal(s.T(), s.service.TokenTTL, result.ExpiresIn)
	})

	s.T().Run("refresh token already used (replay)", func(t *testing.T) {
		req := newReq()
		refreshRec := *validRefreshToken
		refreshRec.Used = true

		s.mockRefreshStore.EXPECT().Find(gomock.Any(), refreshTokenString).Return(&refreshRec, refreshTokenStore.ErrRefreshTokenUsed)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeUnauthorized))
		assert.Contains(s.T(), err.Error(), "invalid refresh token")
	})

	s.T().Run("refresh token not found", func(t *testing.T) {
		req := models.TokenRequest{
			GrantType:    string(models.GrantRefreshToken),
			RefreshToken: "invalid_token",
			ClientID:     clientID,
		}

		s.mockRefreshStore.EXPECT().Find(gomock.Any(), "invalid_token").Return(nil, refreshTokenStore.ErrNotFound)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeUnauthorized))
		assert.Contains(s.T(), err.Error(), "invalid refresh token")
	})

	s.T().Run("refresh token expired", func(t *testing.T) {
		req := newReq()
		refreshRec := *validRefreshToken
		refreshRec.ExpiresAt = time.Now().Add(-1 * time.Hour) // Expired

		s.mockRefreshStore.EXPECT().Find(gomock.Any(), refreshTokenString).Return(&refreshRec, refreshTokenStore.ErrRefreshTokenExpired)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeUnauthorized))
		assert.Contains(s.T(), err.Error(), "expired")
	})

	s.T().Run("session not found for refresh token", func(t *testing.T) {
		req := newReq()
		refreshRec := *validRefreshToken

		s.mockRefreshStore.EXPECT().Find(gomock.Any(), refreshTokenString).Return(&refreshRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(nil, sessionStore.ErrNotFound)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeUnauthorized))
	})

	s.T().Run("session revoked", func(t *testing.T) {
		req := newReq()
		refreshRec := *validRefreshToken
		sess := *validSession
		sess.Status = "revoked"

		s.mockRefreshStore.EXPECT().Find(gomock.Any(), refreshTokenString).Return(&refreshRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), clientUUID.String()).Return(mockClient, mockTenant, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), userID).Return(mockUser, nil)
		s.mockRefreshStore.EXPECT().ConsumeRefreshToken(gomock.Any(), refreshTokenString, gomock.Any()).Return(&refreshRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		expectTokens(t)
		s.mockSessionStore.EXPECT().AdvanceLastRefreshed(gomock.Any(), sess.ID, req.ClientID, gomock.Any(), issuedAccessTokenJTI, sess.DeviceID, sess.DeviceFingerprintHash).
			Return(nil, sessionStore.ErrSessionRevoked)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		// Error gets wrapped by transaction as CodeInternal
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeInternal) || dErrors.Is(err, dErrors.CodeUnauthorized))
	})

	s.T().Run("client_id mismatch", func(t *testing.T) {
		req := models.TokenRequest{
			GrantType:    string(models.GrantRefreshToken),
			RefreshToken: refreshTokenString,
			ClientID:     "evil-client",
		}
		refreshRec := *validRefreshToken
		sess := *validSession

		s.mockRefreshStore.EXPECT().Find(gomock.Any(), refreshTokenString).Return(&refreshRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), clientUUID.String()).Return(mockClient, mockTenant, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), userID).Return(mockUser, nil)
		s.mockRefreshStore.EXPECT().ConsumeRefreshToken(gomock.Any(), refreshTokenString, gomock.Any()).Return(&refreshRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		expectTokens(t)
		s.mockSessionStore.EXPECT().AdvanceLastRefreshed(gomock.Any(), sess.ID, req.ClientID, gomock.Any(), issuedAccessTokenJTI, sess.DeviceID, sess.DeviceFingerprintHash).
			Return(nil, dErrors.New(dErrors.CodeUnauthorized, "client_id mismatch"))

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		// Error gets wrapped by transaction as CodeInternal
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeInternal) || dErrors.Is(err, dErrors.CodeUnauthorized))
	})

	s.T().Run("client inactive - PRD-026A FR-4.5.4", func(t *testing.T) {
		req := newReq()
		refreshRec := *validRefreshToken
		sess := *validSession
		inactiveClient := *mockClient
		inactiveClient.Status = "inactive"

		// Validation happens before transaction
		s.mockRefreshStore.EXPECT().Find(gomock.Any(), refreshTokenString).Return(&refreshRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), clientUUID.String()).Return(&inactiveClient, mockTenant, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), userID).Return(mockUser, nil)
		// Transaction should NOT be entered because validation fails

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		// Should get forbidden error for inactive client (client validation is after token context)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeForbidden))
		assert.Contains(s.T(), err.Error(), "client is not active")
	})

	s.T().Run("user inactive - PRD-026A FR-4.5.4", func(t *testing.T) {
		req := newReq()
		refreshRec := *validRefreshToken
		sess := *validSession
		inactiveUser := *mockUser
		inactiveUser.Status = models.UserStatusInactive

		// Validation happens before transaction
		s.mockRefreshStore.EXPECT().Find(gomock.Any(), refreshTokenString).Return(&refreshRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), clientUUID.String()).Return(mockClient, mockTenant, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), userID).Return(&inactiveUser, nil)
		// Transaction should NOT be entered because validation fails

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		// User inactive propagates as Forbidden from token context
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeForbidden))
		assert.Contains(s.T(), err.Error(), "user inactive")
	})

	s.T().Run("device binding enabled ignores mismatched cookie device_id", func(t *testing.T) {
		req := newReq()
		refreshRec := *validRefreshToken
		sess := *validSession
		sess.DeviceID = "session-device"
		ctx := middleware.WithDeviceID(context.Background(), "cookie-device-1")

		// Enable device binding for this specific scenario
		prevBinding := s.service.DeviceBindingEnabled
		prevDeviceSvc := s.service.deviceService
		s.service.DeviceBindingEnabled = true
		s.service.deviceService = device.NewService(true)
		t.Cleanup(func() {
			s.service.DeviceBindingEnabled = prevBinding
			s.service.deviceService = prevDeviceSvc
		})

		// Validation before transaction
		s.mockRefreshStore.EXPECT().Find(gomock.Any(), refreshTokenString).Return(&refreshRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), clientUUID.String()).Return(mockClient, mockTenant, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), userID).Return(mockUser, nil)
		// Inside transaction
		s.mockRefreshStore.EXPECT().ConsumeRefreshToken(gomock.Any(), refreshTokenString, gomock.Any()).Return(&refreshRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		expectTokens(t)
		s.mockSessionStore.EXPECT().AdvanceLastRefreshed(gomock.Any(), sess.ID, req.ClientID, gomock.Any(), issuedAccessTokenJTI, sess.DeviceID, sess.DeviceFingerprintHash).
			DoAndReturn(func(ctx context.Context, sessionID uuid.UUID, client string, ts time.Time, jti string, deviceID string, fingerprint string) (*models.Session, error) {
				assert.Equal(s.T(), sess.DeviceID, deviceID)
				return &sess, nil
			})
		s.mockRefreshStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		result, err := s.service.Token(ctx, &req)
		require.NoError(s.T(), err)
		assert.NotNil(s.T(), result)
		assert.Equal(s.T(), "session-device", sess.DeviceID)
	})
}
