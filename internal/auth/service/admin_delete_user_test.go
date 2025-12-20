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
