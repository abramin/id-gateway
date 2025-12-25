package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"credo/internal/auth/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	request "credo/pkg/platform/middleware/request"
	"credo/pkg/platform/sentinel"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// TestDeleteUser tests the admin user deletion error handling
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
		s.True(dErrors.HasCode(err, dErrors.CodeInternal))
	})

	s.T().Run("user not found", func(t *testing.T) {
		s.mockUserStore.EXPECT().FindByID(ctx, userID).Return(nil, sentinel.ErrNotFound)

		err := s.service.DeleteUser(ctx, userID)
		require.Error(t, err)
		s.True(dErrors.HasCode(err, dErrors.CodeNotFound))
	})

	s.T().Run("session delete fails", func(t *testing.T) {
		s.mockUserStore.EXPECT().FindByID(ctx, userID).Return(existingUser, nil)
		s.mockSessionStore.EXPECT().DeleteSessionsByUser(ctx, userID).Return(errors.New("redis down"))

		err := s.service.DeleteUser(ctx, userID)
		require.Error(t, err)
		s.True(dErrors.HasCode(err, dErrors.CodeInternal))
	})

	s.T().Run("user delete fails", func(t *testing.T) {
		s.mockUserStore.EXPECT().FindByID(ctx, userID).Return(existingUser, nil)
		s.mockSessionStore.EXPECT().DeleteSessionsByUser(ctx, userID).Return(nil)
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)
		s.mockUserStore.EXPECT().Delete(ctx, userID).Return(errors.New("write fail"))

		err := s.service.DeleteUser(ctx, userID)
		require.Error(t, err)
		s.True(dErrors.HasCode(err, dErrors.CodeInternal))
	})
}

func (s *ServiceSuite) TestDeleteUserAuditEnrichment() {
	userID := id.UserID(uuid.New())
	existingUser := &models.User{ID: userID, Email: "audit-test@example.com"}

	s.T().Run("sessions_revoked event includes email and request_id", func(t *testing.T) {
		ctx := contextWithRequestID("req-12345")

		s.mockUserStore.EXPECT().FindByID(gomock.Any(), userID).Return(existingUser, nil)
		s.mockSessionStore.EXPECT().DeleteSessionsByUser(gomock.Any(), userID).Return(nil)

		var sessionsRevokedEvent audit.Event
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, event audit.Event) error {
				if event.Action == string(audit.EventSessionsRevoked) {
					sessionsRevokedEvent = event
				}
				return nil
			},
		).Times(2) // sessions_revoked and user_deleted

		s.mockUserStore.EXPECT().Delete(gomock.Any(), userID).Return(nil)

		err := s.service.DeleteUser(ctx, userID)
		s.Require().NoError(err)
		s.Equal("audit-test@example.com", sessionsRevokedEvent.Email,
			"sessions_revoked event should include user email per PRD-001B")
		s.Equal("req-12345", sessionsRevokedEvent.RequestID,
			"sessions_revoked event should include request_id per PRD-001B")
	})

	s.T().Run("user_deleted event includes email and request_id", func(t *testing.T) {
		ctx := contextWithRequestID("req-67890")

		s.mockUserStore.EXPECT().FindByID(gomock.Any(), userID).Return(existingUser, nil)
		s.mockSessionStore.EXPECT().DeleteSessionsByUser(gomock.Any(), userID).Return(nil)

		// Capture the user_deleted event
		var userDeletedEvent audit.Event
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, event audit.Event) error {
				if event.Action == string(audit.EventUserDeleted) {
					userDeletedEvent = event
				}
				return nil
			},
		).Times(2)

		s.mockUserStore.EXPECT().Delete(gomock.Any(), userID).Return(nil)

		err := s.service.DeleteUser(ctx, userID)
		s.Require().NoError(err)
		s.Equal("audit-test@example.com", userDeletedEvent.Email,
			"user_deleted event should include user email per PRD-001B")

		s.Equal("req-67890", userDeletedEvent.RequestID,
			"user_deleted event should include request_id per PRD-001B")
	})
}

// =============================================================================
// Audit Event Enrichment Tests
// =============================================================================
// - user_id (implemented)
// - email (when available)
// - request_id (from context)

// contextWithRequestID creates a context with request_id set via the request middleware.
// This mimics what happens when an HTTP request passes through the RequestID middleware.
func contextWithRequestID(requestID string) context.Context {
	req := httptest.NewRequest(http.MethodDelete, "/admin/auth/users/123", nil)
	req.Header.Set("X-Request-ID", requestID)

	var ctx context.Context
	handler := request.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx = r.Context()
	}))
	handler.ServeHTTP(httptest.NewRecorder(), req)
	return ctx
}
