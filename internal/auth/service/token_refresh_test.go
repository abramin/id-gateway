package service

import (
	"context"
	"testing"
	"time"

	"credo/internal/auth/device"
	"credo/internal/auth/models"
	sessionStore "credo/internal/auth/store/session"
	"credo/internal/platform/middleware"
	dErrors "credo/pkg/domain-errors"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func (s *ServiceSuite) TestToken_RefreshToken() {
	sessionID := uuid.New()
	userID := uuid.New()
	clientID := "client-123"
	refreshTokenString := "ref_abc123xyz"

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
		ClientID:       clientID,
		RequestedScope: []string{"openid", "profile"},
		DeviceID:       "device-123",
		Status:         StatusActive,
		CreatedAt:      time.Now().Add(-1 * time.Hour),
		ExpiresAt:      time.Now().Add(23 * time.Hour),
	}

	s.T().Run("happy path - successful token refresh", func(t *testing.T) {
		req := models.TokenRequest{
			GrantType:    "refresh_token",
			RefreshToken: refreshTokenString,
			ClientID:     clientID,
		}
		refreshRec := *validRefreshToken
		sess := *validSession
		ctx := context.Background()

		// Expected flow:
		s.mockRefreshStore.EXPECT().Find(gomock.Any(), refreshTokenString).Return(&refreshRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockJWT.EXPECT().GenerateAccessToken(userID, sessionID, clientID).Return("new-access-token", nil)
		s.mockJWT.EXPECT().GenerateIDToken(userID, sessionID, clientID).Return("new-id-token", nil)
		s.mockJWT.EXPECT().CreateRefreshToken().Return("ref_new_token", nil)
		// Inside RunInTx: UpdateSession, mark old token used, create new token
		s.mockSessionStore.EXPECT().UpdateSession(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, session *models.Session) error {
				assert.Equal(s.T(), sess.ID, session.ID)
				assert.NotNil(s.T(), session.LastSeenAt)
				assert.NotNil(s.T(), session.LastRefreshedAt)
				return nil
			})
		s.mockRefreshStore.EXPECT().Consume(gomock.Any(), refreshTokenString, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tokenString string, timestamp time.Time) error {
				assert.Equal(s.T(), refreshTokenString, tokenString)
				assert.False(s.T(), timestamp.IsZero())
				return nil
			})
		s.mockRefreshStore.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, token *models.RefreshTokenRecord) error {
				assert.Equal(s.T(), "ref_new_token", token.Token)
				assert.Equal(s.T(), sessionID, token.SessionID)
				assert.False(s.T(), token.Used)
				return nil
			})
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		result, err := s.service.Token(ctx, &req)
		require.NoError(s.T(), err)
		assert.Equal(s.T(), "new-access-token", result.AccessToken)
		assert.Equal(s.T(), "new-id-token", result.IDToken)
		assert.Equal(s.T(), "ref_new_token", result.RefreshToken)
		assert.Equal(s.T(), "Bearer", result.TokenType)
		assert.Equal(s.T(), s.service.TokenTTL, result.ExpiresIn)
	})

	s.T().Run("refresh token already used (replay)", func(t *testing.T) {
		req := models.TokenRequest{
			GrantType:    "refresh_token",
			RefreshToken: refreshTokenString,
			ClientID:     clientID,
		}
		refreshRec := *validRefreshToken
		refreshRec.Used = true

		s.mockRefreshStore.EXPECT().Find(gomock.Any(), refreshTokenString).Return(&refreshRec, nil)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeUnauthorized))
		assert.Contains(s.T(), err.Error(), "invalid refresh token")
	})

	s.T().Run("refresh token not found", func(t *testing.T) {
		req := models.TokenRequest{
			GrantType:    "refresh_token",
			RefreshToken: "invalid_token",
			ClientID:     clientID,
		}

		s.mockRefreshStore.EXPECT().Find(gomock.Any(), "invalid_token").Return(nil, sessionStore.ErrNotFound)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeUnauthorized))
		assert.Contains(s.T(), err.Error(), "invalid refresh token")
	})

	s.T().Run("refresh token expired", func(t *testing.T) {
		req := models.TokenRequest{
			GrantType:    "refresh_token",
			RefreshToken: refreshTokenString,
			ClientID:     clientID,
		}
		refreshRec := *validRefreshToken
		refreshRec.ExpiresAt = time.Now().Add(-1 * time.Hour) // Expired

		s.mockRefreshStore.EXPECT().Find(gomock.Any(), refreshTokenString).Return(&refreshRec, nil)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeUnauthorized))
		assert.Contains(s.T(), err.Error(), "expired")
	})

	s.T().Run("session not found for refresh token", func(t *testing.T) {
		req := models.TokenRequest{
			GrantType:    "refresh_token",
			RefreshToken: refreshTokenString,
			ClientID:     clientID,
		}
		refreshRec := *validRefreshToken

		s.mockRefreshStore.EXPECT().Find(gomock.Any(), refreshTokenString).Return(&refreshRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(nil, sessionStore.ErrNotFound)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeUnauthorized))
	})

	s.T().Run("session revoked", func(t *testing.T) {
		req := models.TokenRequest{
			GrantType:    "refresh_token",
			RefreshToken: refreshTokenString,
			ClientID:     clientID,
		}
		refreshRec := *validRefreshToken
		sess := *validSession
		sess.Status = "revoked"

		s.mockRefreshStore.EXPECT().Find(gomock.Any(), refreshTokenString).Return(&refreshRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeUnauthorized))
		assert.Contains(s.T(), err.Error(), "revoked")
	})

	s.T().Run("client_id mismatch", func(t *testing.T) {
		req := models.TokenRequest{
			GrantType:    "refresh_token",
			RefreshToken: refreshTokenString,
			ClientID:     "evil-client",
		}
		refreshRec := *validRefreshToken
		sess := *validSession

		s.mockRefreshStore.EXPECT().Find(gomock.Any(), refreshTokenString).Return(&refreshRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeUnauthorized))
		assert.Contains(s.T(), err.Error(), "client_id mismatch")
	})

	s.T().Run("device binding enabled ignores mismatched cookie device_id", func(t *testing.T) {
		req := models.TokenRequest{
			GrantType:    "refresh_token",
			RefreshToken: refreshTokenString,
			ClientID:     clientID,
		}
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

		s.mockRefreshStore.EXPECT().Find(gomock.Any(), refreshTokenString).Return(&refreshRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockJWT.EXPECT().GenerateAccessToken(userID, sessionID, clientID).Return("new-access-token", nil)
		s.mockJWT.EXPECT().GenerateIDToken(userID, sessionID, clientID).Return("new-id-token", nil)
		s.mockJWT.EXPECT().CreateRefreshToken().Return("ref_new_token", nil)
		s.mockSessionStore.EXPECT().UpdateSession(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, session *models.Session) error {
				assert.Equal(s.T(), sess.DeviceID, session.DeviceID)
				return nil
			})
		s.mockRefreshStore.EXPECT().Consume(gomock.Any(), refreshTokenString, gomock.Any()).Return(nil)
		s.mockRefreshStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		result, err := s.service.Token(ctx, &req)
		require.NoError(s.T(), err)
		assert.NotNil(s.T(), result)
		assert.Equal(s.T(), "session-device", sess.DeviceID)
	})
}
