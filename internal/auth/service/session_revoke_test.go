package service

import (
	"context"
	"testing"

	"credo/internal/auth/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// TestService_RevokeSession tests session revocation (PRD-016)
//
// AGENTS.MD JUSTIFICATION (per testing.md doctrine):
// These unit tests verify behaviors NOT covered by Gherkin:
// - validation errors: Tests input validation error codes (fast feedback)
// - session not found: Tests error propagation from store
// - different user forbidden: Tests multi-user authorization check (unique)
//
// REMOVED per testing.md (duplicate of e2e/features/auth_token_lifecycle.feature):
// - "active session owned by user revoked" - covered by "Revoke session by session_id"
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
