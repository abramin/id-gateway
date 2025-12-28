package service

import (
	"context"

	"credo/internal/auth/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// TestSessionRevocation_ValidationAndAuthorization tests session revocation (PRD-016)
//
// AGENTS.MD JUSTIFICATION (per testing.md doctrine):
// These unit tests verify behaviors NOT covered by Gherkin:
// - validation errors: Tests input validation error codes (fast feedback)
// - session not found: Tests error propagation from store
// - different user forbidden: Tests multi-user authorization check (unique)
func (s *ServiceSuite) TestSessionRevocation_ValidationAndAuthorization() {
	ctx := context.Background()

	s.Run("Given invalid user When revoke Then unauthorized", func() {
		err := s.service.RevokeSession(ctx, id.UserID(uuid.Nil), id.SessionID(uuid.New()))
		s.Require().Error(err)
		s.True(dErrors.HasCode(err, dErrors.CodeUnauthorized))
	})

	s.Run("Given missing session id When revoke Then bad request", func() {
		err := s.service.RevokeSession(ctx, id.UserID(uuid.New()), id.SessionID(uuid.Nil))
		s.Require().Error(err)
		s.True(dErrors.HasCode(err, dErrors.CodeBadRequest))
	})

	s.Run("Given session not found When revoke Then not found", func() {
		userID := id.UserID(uuid.New())
		sessionID := id.SessionID(uuid.New())
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(nil, dErrors.New(dErrors.CodeNotFound, "nope"))

		err := s.service.RevokeSession(ctx, userID, sessionID)
		s.Require().Error(err)
		s.True(dErrors.HasCode(err, dErrors.CodeNotFound))
	})

	s.Run("Given session belongs to different user When revoke Then forbidden", func() {
		userID := id.UserID(uuid.New())
		otherUserID := id.UserID(uuid.New())
		sessionID := id.SessionID(uuid.New())
		session := &models.Session{
			ID:     sessionID,
			UserID: otherUserID,
			Status: models.SessionStatusActive,
		}
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(session, nil)
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		err := s.service.RevokeSession(ctx, userID, sessionID)
		s.Require().Error(err)
		s.True(dErrors.HasCode(err, dErrors.CodeForbidden))
	})
}

func (s *ServiceSuite) TestSessionRevocation_LogoutAll() {
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

	s.Run("Given user with multiple sessions When logout_all except_current=true Then revoke all except current", func() {
		s.mockSessionStore.EXPECT().ListByUser(gomock.Any(), userID).Return(sessions, nil)
		// Should revoke 2 sessions (not the current one)
		s.mockSessionStore.EXPECT().RevokeSessionIfActive(gomock.Any(), sessions[1].ID, gomock.Any()).Return(nil)
		s.mockSessionStore.EXPECT().RevokeSessionIfActive(gomock.Any(), sessions[2].ID, gomock.Any()).Return(nil)
		s.mockRefreshStore.EXPECT().DeleteBySessionID(gomock.Any(), sessions[1].ID).Return(nil)
		s.mockRefreshStore.EXPECT().DeleteBySessionID(gomock.Any(), sessions[2].ID).Return(nil)
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		result, err := s.service.LogoutAll(ctx, userID, currentSessionID, true)

		s.Require().NoError(err)
		s.Equal(2, result.RevokedCount)
	})

	s.Run("Given user with multiple sessions When logout_all except_current=false Then revoke all including current", func() {
		s.mockSessionStore.EXPECT().ListByUser(gomock.Any(), userID).Return(sessions, nil)
		// Should revoke all 3 sessions
		s.mockSessionStore.EXPECT().RevokeSessionIfActive(gomock.Any(), sessions[0].ID, gomock.Any()).Return(nil)
		s.mockSessionStore.EXPECT().RevokeSessionIfActive(gomock.Any(), sessions[1].ID, gomock.Any()).Return(nil)
		s.mockSessionStore.EXPECT().RevokeSessionIfActive(gomock.Any(), sessions[2].ID, gomock.Any()).Return(nil)
		s.mockRefreshStore.EXPECT().DeleteBySessionID(gomock.Any(), sessions[0].ID).Return(nil)
		s.mockRefreshStore.EXPECT().DeleteBySessionID(gomock.Any(), sessions[1].ID).Return(nil)
		s.mockRefreshStore.EXPECT().DeleteBySessionID(gomock.Any(), sessions[2].ID).Return(nil)
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		result, err := s.service.LogoutAll(ctx, userID, currentSessionID, false)

		s.Require().NoError(err)
		s.Equal(3, result.RevokedCount)
	})

	s.Run("Given invalid user ID When logout_all Then unauthorized", func() {
		_, err := s.service.LogoutAll(ctx, id.UserID(uuid.Nil), currentSessionID, true)

		s.Require().Error(err)
		s.True(dErrors.HasCode(err, dErrors.CodeUnauthorized))
	})

	s.Run("Given session store error When logout_all Then internal error", func() {
		s.mockSessionStore.EXPECT().ListByUser(gomock.Any(), userID).Return(nil, assert.AnError)

		_, err := s.service.LogoutAll(ctx, userID, currentSessionID, true)

		s.Require().Error(err)
		s.True(dErrors.HasCode(err, dErrors.CodeInternal))
	})
}
