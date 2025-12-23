package service

import (
	"context"
	"errors"
	"testing"

	"credo/internal/auth/models"
	userStore "credo/internal/auth/store/user"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// TestDeleteUser tests the admin user deletion error handling (PRD-001B)
// NOTE: Happy path and no-sessions-found cases are covered by Cucumber E2E tests
// in e2e/features/admin_gdpr.feature. These unit tests focus on error propagation.
func (s *ServiceSuite) TestDeleteUser() {
	ctx := context.Background()
	userID := id.UserID(uuid.New())
	existingUser := &models.User{ID: userID, Email: "user@example.com"}

	s.T().Run("user lookup fails", func(t *testing.T) {
		s.mockUserStore.EXPECT().FindByID(ctx, userID).Return(nil, errors.New("db down"))

		err := s.service.DeleteUser(ctx, userID)
		require.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeInternal))
	})

	s.T().Run("user not found", func(t *testing.T) {
		s.mockUserStore.EXPECT().FindByID(ctx, userID).Return(nil, userStore.ErrNotFound)

		err := s.service.DeleteUser(ctx, userID)
		require.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeNotFound))
	})

	s.T().Run("session delete fails", func(t *testing.T) {
		s.mockUserStore.EXPECT().FindByID(ctx, userID).Return(existingUser, nil)
		s.mockSessionStore.EXPECT().DeleteSessionsByUser(ctx, userID).Return(errors.New("redis down"))

		err := s.service.DeleteUser(ctx, userID)
		require.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeInternal))
	})

	s.T().Run("user delete fails", func(t *testing.T) {
		s.mockUserStore.EXPECT().FindByID(ctx, userID).Return(existingUser, nil)
		s.mockSessionStore.EXPECT().DeleteSessionsByUser(ctx, userID).Return(nil)
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)
		s.mockUserStore.EXPECT().Delete(ctx, userID).Return(errors.New("write fail"))

		err := s.service.DeleteUser(ctx, userID)
		require.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeInternal))
	})
}

// =============================================================================
// Audit Event Enrichment Tests (PRD-001B Known Gap)
// =============================================================================
// PRD-001B specifies that audit events should include:
// - user_id (currently implemented)
// - email (when available) - NOT YET IMPLEMENTED
// - request_id (from context) - NOT YET IMPLEMENTED
// These tests document the expected behavior and will FAIL until implemented.

func (s *ServiceSuite) TestDeleteUserAuditEnrichment() {
	userID := id.UserID(uuid.New())
	existingUser := &models.User{ID: userID, Email: "audit-test@example.com"}

	s.T().Run("sessions_revoked event includes email and request_id", func(t *testing.T) {
		// Create context with request_id
		ctx := context.WithValue(context.Background(), "request_id", "req-12345")

		s.mockUserStore.EXPECT().FindByID(ctx, userID).Return(existingUser, nil)
		s.mockSessionStore.EXPECT().DeleteSessionsByUser(ctx, userID).Return(nil)

		// Capture the sessions_revoked event
		var sessionsRevokedEvent map[string]interface{}
		s.mockAuditPublisher.EXPECT().Emit(ctx, gomock.Any()).DoAndReturn(
			func(_ context.Context, event interface{}) error {
				if e, ok := event.(map[string]interface{}); ok {
					if e["event_type"] == "sessions_revoked" {
						sessionsRevokedEvent = e
					}
				}
				return nil
			},
		).Times(2) // sessions_revoked and user_deleted

		s.mockUserStore.EXPECT().Delete(ctx, userID).Return(nil)

		err := s.service.DeleteUser(ctx, userID)
		require.NoError(t, err)

		// PRD-001B: Audit events should include email when available
		assert.Equal(t, "audit-test@example.com", sessionsRevokedEvent["email"],
			"sessions_revoked event should include user email per PRD-001B")

		// PRD-001B: Audit events should include request_id from context
		assert.Equal(t, "req-12345", sessionsRevokedEvent["request_id"],
			"sessions_revoked event should include request_id per PRD-001B")
	})

	s.T().Run("user_deleted event includes email and request_id", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), "request_id", "req-67890")

		s.mockUserStore.EXPECT().FindByID(ctx, userID).Return(existingUser, nil)
		s.mockSessionStore.EXPECT().DeleteSessionsByUser(ctx, userID).Return(nil)

		// Capture the user_deleted event
		var userDeletedEvent map[string]interface{}
		s.mockAuditPublisher.EXPECT().Emit(ctx, gomock.Any()).DoAndReturn(
			func(_ context.Context, event interface{}) error {
				if e, ok := event.(map[string]interface{}); ok {
					if e["event_type"] == "user_deleted" {
						userDeletedEvent = e
					}
				}
				return nil
			},
		).Times(2)

		s.mockUserStore.EXPECT().Delete(ctx, userID).Return(nil)

		err := s.service.DeleteUser(ctx, userID)
		require.NoError(t, err)

		// PRD-001B: Audit events should include email when available
		assert.Equal(t, "audit-test@example.com", userDeletedEvent["email"],
			"user_deleted event should include user email per PRD-001B")

		// PRD-001B: Audit events should include request_id from context
		assert.Equal(t, "req-67890", userDeletedEvent["request_id"],
			"user_deleted event should include request_id per PRD-001B")
	})
}
