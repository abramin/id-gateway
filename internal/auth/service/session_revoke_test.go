package service

import (
	"context"
	"testing"

	"credo/internal/auth/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// TestService_RevokeSession tests session revocation (PRD-016)
//
// AGENTS.MD JUSTIFICATION (per testing.md doctrine):
// These unit tests verify behaviors NOT covered by Gherkin:
// - validation errors: Tests input validation error codes (fast feedback)
// - session not found: Tests error propagation from store
// - different user forbidden: Tests multi-user authorization check (unique)
func (s *ServiceSuite) TestService_RevokeSession() {
	ctx := context.Background()

	s.T().Run("Given invalid user When revoke Then unauthorized", func(t *testing.T) {
		err := s.service.RevokeSession(ctx, id.UserID(uuid.Nil), id.SessionID(uuid.New()))
		assert.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeUnauthorized))
	})

	s.T().Run("Given missing session id When revoke Then bad request", func(t *testing.T) {
		err := s.service.RevokeSession(ctx, id.UserID(uuid.New()), id.SessionID(uuid.Nil))
		assert.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeBadRequest))
	})

	s.T().Run("Given session not found When revoke Then not found", func(t *testing.T) {
		userID := id.UserID(uuid.New())
		sessionID := id.SessionID(uuid.New())
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(nil, dErrors.New(dErrors.CodeNotFound, "nope"))

		err := s.service.RevokeSession(ctx, userID, sessionID)
		assert.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeNotFound))
	})

	s.T().Run("Given session belongs to different user When revoke Then forbidden", func(t *testing.T) {
		userID := id.UserID(uuid.New())
		otherUserID := id.UserID(uuid.New())
		sessionID := id.SessionID(uuid.New())
		session := &models.Session{
			ID:     sessionID,
			UserID: otherUserID,
			Status: models.SessionStatusActive,
		}
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(session, nil)

		err := s.service.RevokeSession(ctx, userID, sessionID)
		assert.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeForbidden))
	})
}

func (s *ServiceSuite) TestLogoutAll() {
	ctx := context.Background()
	userID := id.UserID(uuid.New())
	currentSessionID := id.SessionID(uuid.New())

	sessions := []*models.Session{
		{
			ID:     currentSessionID,
			UserID: userID,
			Status: models.SessionStatusActive,
		},
		{
			ID:     id.SessionID(uuid.New()),
			UserID: userID,
			Status: models.SessionStatusActive,
		},
		{
			ID:     id.SessionID(uuid.New()),
			UserID: userID,
			Status: models.SessionStatusActive,
		},
	}

	s.T().Run("Given user with multiple sessions When logout_all except_current=true Then revoke all except current", func(t *testing.T) {
		s.mockSessionStore.EXPECT().ListByUser(gomock.Any(), userID).Return(sessions, nil)
		// Should revoke 2 sessions (not the current one)
		s.mockSessionStore.EXPECT().RevokeSessionIfActive(gomock.Any(), sessions[1].ID, gomock.Any()).Return(nil)
		s.mockSessionStore.EXPECT().RevokeSessionIfActive(gomock.Any(), sessions[2].ID, gomock.Any()).Return(nil)
		s.mockRefreshStore.EXPECT().DeleteBySessionID(gomock.Any(), sessions[1].ID).Return(nil)
		s.mockRefreshStore.EXPECT().DeleteBySessionID(gomock.Any(), sessions[2].ID).Return(nil)
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil).Times(2)

		result, err := s.service.LogoutAll(ctx, userID, currentSessionID, true)

		require.NoError(t, err)
		assert.Equal(t, 2, result.RevokedCount)
	})

	s.T().Run("Given user with multiple sessions When logout_all except_current=false Then revoke all including current", func(t *testing.T) {
		s.mockSessionStore.EXPECT().ListByUser(gomock.Any(), userID).Return(sessions, nil)
		// Should revoke all 3 sessions
		s.mockSessionStore.EXPECT().RevokeSessionIfActive(gomock.Any(), sessions[0].ID, gomock.Any()).Return(nil)
		s.mockSessionStore.EXPECT().RevokeSessionIfActive(gomock.Any(), sessions[1].ID, gomock.Any()).Return(nil)
		s.mockSessionStore.EXPECT().RevokeSessionIfActive(gomock.Any(), sessions[2].ID, gomock.Any()).Return(nil)
		s.mockRefreshStore.EXPECT().DeleteBySessionID(gomock.Any(), sessions[0].ID).Return(nil)
		s.mockRefreshStore.EXPECT().DeleteBySessionID(gomock.Any(), sessions[1].ID).Return(nil)
		s.mockRefreshStore.EXPECT().DeleteBySessionID(gomock.Any(), sessions[2].ID).Return(nil)
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil).Times(3)

		result, err := s.service.LogoutAll(ctx, userID, currentSessionID, false)

		require.NoError(t, err)
		assert.Equal(t, 3, result.RevokedCount)
	})

	s.T().Run("Given invalid user ID When logout_all Then unauthorized", func(t *testing.T) {
		_, err := s.service.LogoutAll(ctx, id.UserID(uuid.Nil), currentSessionID, true)

		require.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeUnauthorized))
	})

	s.T().Run("Given session store error When logout_all Then internal error", func(t *testing.T) {
		s.mockSessionStore.EXPECT().ListByUser(gomock.Any(), userID).Return(nil, assert.AnError)

		_, err := s.service.LogoutAll(ctx, userID, currentSessionID, true)

		require.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeInternal))
	})
}
