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

// TestLogoutAll tests the global session revocation (PRD-016 FR-6)
//
// AGENTS.MD JUSTIFICATION (per testing.md doctrine):
// These unit tests verify the LogoutAll method behavior:
// - Revoke all sessions except current when except_current=true
// - Revoke all sessions including current when except_current=false
// - Error handling for invalid user ID
// - Error handling for store failures
func (s *ServiceSuite) TestLogoutAll() {
	ctx := context.Background()
	userID := id.UserID(uuid.New())
	currentSessionID := id.SessionID(uuid.New())

	// Create mock sessions - user has 3 active sessions
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
		// Expect: List sessions, revoke all except current, return count

		s.mockSessionStore.EXPECT().ListByUser(gomock.Any(), userID).Return(sessions, nil)
		// Should revoke 2 sessions (not the current one)
		s.mockSessionStore.EXPECT().RevokeSession(gomock.Any(), sessions[1].ID).Return(nil)
		s.mockSessionStore.EXPECT().RevokeSession(gomock.Any(), sessions[2].ID).Return(nil)
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		result, err := s.service.LogoutAll(ctx, userID, currentSessionID, true)

		require.NoError(t, err)
		assert.Equal(t, 2, result.RevokedCount)
	})

	s.T().Run("Given user with multiple sessions When logout_all except_current=false Then revoke all including current", func(t *testing.T) {
		s.mockSessionStore.EXPECT().ListByUser(gomock.Any(), userID).Return(sessions, nil)
		// Should revoke all 3 sessions
		s.mockSessionStore.EXPECT().RevokeSession(gomock.Any(), sessions[0].ID).Return(nil)
		s.mockSessionStore.EXPECT().RevokeSession(gomock.Any(), sessions[1].ID).Return(nil)
		s.mockSessionStore.EXPECT().RevokeSession(gomock.Any(), sessions[2].ID).Return(nil)
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

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
