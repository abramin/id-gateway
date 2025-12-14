package service

import (
	"context"
	"testing"

	"credo/internal/auth/models"
	dErrors "credo/pkg/domain-errors"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func (s *ServiceSuite) TestService_RevokeSession() {
	ctx := context.Background()

	s.T().Run("Given invalid user When revoke Then unauthorized", func(t *testing.T) {
		err := s.service.RevokeSession(ctx, uuid.Nil, uuid.New())
		assert.Error(t, err)
		assert.True(t, dErrors.Is(err, dErrors.CodeUnauthorized))
	})

	s.T().Run("Given missing session id When revoke Then bad request", func(t *testing.T) {
		err := s.service.RevokeSession(ctx, uuid.New(), uuid.Nil)
		assert.Error(t, err)
		assert.True(t, dErrors.Is(err, dErrors.CodeBadRequest))
	})

	s.T().Run("Given session not found When revoke Then not found", func(t *testing.T) {
		userID := uuid.New()
		sessionID := uuid.New()
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(nil, dErrors.New(dErrors.CodeNotFound, "nope"))

		err := s.service.RevokeSession(ctx, userID, sessionID)
		assert.Error(t, err)
		assert.True(t, dErrors.Is(err, dErrors.CodeNotFound))
	})

	s.T().Run("Given session belongs to different user When revoke Then forbidden", func(t *testing.T) {
		userID := uuid.New()
		otherUserID := uuid.New()
		sessionID := uuid.New()
		session := &models.Session{
			ID:     sessionID,
			UserID: otherUserID,
			Status: string(models.SessionStatusActive),
		}
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(session, nil)

		err := s.service.RevokeSession(ctx, userID, sessionID)
		assert.Error(t, err)
		assert.True(t, dErrors.Is(err, dErrors.CodeForbidden))
	})

	s.T().Run("Given active session owned by user When revoke Then session revoked and token JTI revoked", func(t *testing.T) {
		userID := uuid.New()
		sessionID := uuid.New()
		jti := uuid.NewString()
		session := &models.Session{
			ID:                 sessionID,
			UserID:             userID,
			ClientID:           "demo-client",
			Status:             string(models.SessionStatusActive),
			LastAccessTokenJTI: jti,
		}

		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(session, nil)
		s.mockSessionStore.EXPECT().RevokeSessionIfActive(gomock.Any(), sessionID, gomock.Any()).Return(nil)
		s.mockRefreshStore.EXPECT().DeleteBySessionID(gomock.Any(), sessionID).Return(nil)
		s.mockTRL.EXPECT().RevokeToken(gomock.Any(), jti, s.service.TokenTTL).Return(nil)
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)
		s.mockTRL.EXPECT().IsRevoked(gomock.Any(), jti).Return(true, nil)

		err := s.service.RevokeSession(ctx, userID, sessionID)
		assert.NoError(t, err)

		revoked, err := s.service.IsTokenRevoked(ctx, jti)
		assert.NoError(t, err)
		assert.True(t, revoked)
	})
}
