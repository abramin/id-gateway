package service

import (
	"context"
	"time"

	"credo/internal/auth/device"
	"credo/internal/auth/models"
	tenantModels "credo/internal/tenant/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	devicectx "credo/pkg/platform/middleware/device"

	"github.com/google/uuid"
	"go.uber.org/mock/gomock"
)

// TestTokenRefreshFlow tests refresh token grant (PRD-016 FR-2)
//
// AGENTS.MD JUSTIFICATION:
// These unit tests verify:
// - Refresh token consumption (single-use enforcement)
// - Client/user status validation on refresh (PRD-026A FR-4.5.4)
// - Token rotation behavior and session advancement
// - Store error propagation to domain errors
//
// E2E coverage: e2e/features/auth_token_lifecycle.feature covers happy path
// and reuse rejection. Unit tests add client/user inactive scenarios.
func (s *ServiceSuite) TestTokenRefreshFlow() {
	sessionID := id.SessionID(uuid.New())
	userID := id.UserID(uuid.New())
	clientUUID := id.ClientID(uuid.New())
	tenantID := id.TenantID(uuid.New())
	clientID := "client-123"
	refreshTokenString := "ref_abc123xyz"

	mockClient, mockTenant := s.newTestClient(tenantID, clientUUID)
	mockUser := s.newTestUser(userID, tenantID)

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
		Status:         models.SessionStatusActive,
		CreatedAt:      time.Now().Add(-1 * time.Hour),
		ExpiresAt:      time.Now().Add(23 * time.Hour),
	}

	s.Run("happy path - successful token refresh", func() {
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
		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), clientID).Return(mockClient, mockTenant, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), userID).Return(mockUser, nil)
		// 4. Inside transaction: consume refresh token, re-find session, generate tokens
		s.mockRefreshStore.EXPECT().ConsumeRefreshToken(gomock.Any(), refreshTokenString, gomock.Any()).Return(&refreshRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		accessToken, accessTokenJTI, idToken, refreshToken := s.expectTokenGeneration(userID, sessionID, clientUUID, tenantID, sess.RequestedScope)
		// Inside RunInTx: Advance session, create new token
		s.mockSessionStore.EXPECT().AdvanceLastRefreshed(gomock.Any(), sess.ID, clientUUID, gomock.Any(), accessTokenJTI, sess.DeviceID, sess.DeviceFingerprintHash).DoAndReturn(
			func(ctx context.Context, sessionID id.SessionID, clientID id.ClientID, ts time.Time, jti string, deviceID string, fingerprint string) (*models.Session, error) {
				s.Require().Equal(sess.ID, sessionID)
				s.Require().False(ts.IsZero())
				s.Require().Equal(accessTokenJTI, jti)
				return &sess, nil
			})
		s.mockRefreshStore.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, token *models.RefreshTokenRecord) error {
				s.Require().Equal(refreshToken, token.Token)
				s.Require().Equal(sessionID, token.SessionID)
				s.Require().False(token.Used)
				return nil
			})
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		result, err := s.service.Token(ctx, &req)
		s.Require().NoError(err)
		s.Equal(accessToken, result.AccessToken)
		s.Equal(idToken, result.IDToken)
		s.Equal(refreshToken, result.RefreshToken)
		s.Equal("Bearer", result.TokenType)
		s.Equal(int(s.service.TokenTTL.Seconds()), result.ExpiresIn)
	})

	// NOTE: RFC 6749 §5.2 invalid_grant scenarios (token used, not found, expired, session not found, session revoked)
	// are covered by e2e/features/auth_token_lifecycle.feature - deleted per testing.md doctrine

	// RFC 6749 §5.2: "The provided authorization grant ... was issued to another client."
	s.Run("client_id mismatch - invalid_grant", func() {
		req := models.TokenRequest{
			GrantType:    string(models.GrantRefreshToken),
			RefreshToken: refreshTokenString,
			ClientID:     "evil-client",
		}
		refreshRec := *validRefreshToken
		sess := *validSession
		otherClient := *mockClient
		otherClient.ID = id.ClientID(uuid.New())
		otherClient.OAuthClientID = req.ClientID

		s.mockRefreshStore.EXPECT().Find(gomock.Any(), refreshTokenString).Return(&refreshRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), req.ClientID).Return(&otherClient, mockTenant, nil)
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		result, err := s.service.Token(context.Background(), &req)
		s.Require().Error(err)
		s.Nil(result)
		// RFC 6749 §5.2: token issued to another client returns invalid_grant
		s.True(dErrors.HasCode(err, dErrors.CodeInvalidGrant),
			"expected invalid_grant error code per RFC 6749 §5.2 - got %s", err.Error())
	})

	s.Run("client inactive - PRD-026A FR-4.5.4", func() {
		req := newReq()
		refreshRec := *validRefreshToken
		sess := *validSession
		inactiveClient := *mockClient
		inactiveClient.Status = tenantModels.ClientStatusInactive

		// Validation happens before transaction
		s.mockRefreshStore.EXPECT().Find(gomock.Any(), refreshTokenString).Return(&refreshRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), clientID).Return(&inactiveClient, mockTenant, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), userID).Return(mockUser, nil)
		// Transaction should NOT be entered because validation fails

		result, err := s.service.Token(context.Background(), &req)
		s.Require().Error(err)
		s.Nil(result)
		// Should get forbidden error for inactive client (client validation is after token context)
		s.True(dErrors.HasCode(err, dErrors.CodeForbidden))
		s.Contains(err.Error(), "client is not active")
	})

	s.Run("user inactive - PRD-026A FR-4.5.4", func() {
		req := newReq()
		refreshRec := *validRefreshToken
		sess := *validSession
		inactiveUser := *mockUser
		inactiveUser.Status = models.UserStatusInactive

		// Validation happens before transaction
		s.mockRefreshStore.EXPECT().Find(gomock.Any(), refreshTokenString).Return(&refreshRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), clientID).Return(mockClient, mockTenant, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), userID).Return(&inactiveUser, nil)
		// Transaction should NOT be entered because validation fails

		result, err := s.service.Token(context.Background(), &req)
		s.Require().Error(err)
		s.Nil(result)
		// User inactive propagates as Forbidden from token context
		s.True(dErrors.HasCode(err, dErrors.CodeForbidden))
		s.Contains(err.Error(), "user inactive")
	})

	s.Run("device binding enabled ignores mismatched cookie device_id", func() {
		req := newReq()
		refreshRec := *validRefreshToken
		sess := *validSession
		sess.DeviceID = "session-device"
		ctx := devicectx.WithDeviceID(context.Background(), "cookie-device-1")

		// Enable device binding for this specific scenario
		prevBinding := s.service.DeviceBindingEnabled
		prevDeviceSvc := s.service.deviceService
		s.service.DeviceBindingEnabled = true
		s.service.deviceService = device.NewService(true)
		s.T().Cleanup(func() {
			s.service.DeviceBindingEnabled = prevBinding
			s.service.deviceService = prevDeviceSvc
		})

		// Validation before transaction
		s.mockRefreshStore.EXPECT().Find(gomock.Any(), refreshTokenString).Return(&refreshRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), clientID).Return(mockClient, mockTenant, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), userID).Return(mockUser, nil)
		// Inside transaction
		s.mockRefreshStore.EXPECT().ConsumeRefreshToken(gomock.Any(), refreshTokenString, gomock.Any()).Return(&refreshRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		_, accessTokenJTI, _, _ := s.expectTokenGeneration(userID, sessionID, clientUUID, tenantID, sess.RequestedScope)
		s.mockSessionStore.EXPECT().AdvanceLastRefreshed(gomock.Any(), sess.ID, clientUUID, gomock.Any(), accessTokenJTI, sess.DeviceID, sess.DeviceFingerprintHash).
			DoAndReturn(func(ctx context.Context, sessionID id.SessionID, client id.ClientID, ts time.Time, jti string, deviceID string, fingerprint string) (*models.Session, error) {
				s.Require().Equal(sess.DeviceID, deviceID)
				return &sess, nil
			})
		s.mockRefreshStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		result, err := s.service.Token(ctx, &req)
		s.Require().NoError(err)
		s.NotNil(result)
		s.Equal("session-device", sess.DeviceID)
	})
}
