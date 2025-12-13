package service

import (
	"context"
	"errors"
	"testing"

	"credo/internal/auth/models"
	sessionStore "credo/internal/auth/store/session"
	userStore "credo/internal/auth/store/user"
	dErrors "credo/pkg/domain-errors"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// TestDeleteUser tests the admin user deletion endpoint (PRD-001B)
func (s *ServiceSuite) TestDeleteUser() {
	ctx := context.Background()
	userID := uuid.New()
	existingUser := &models.User{ID: userID, Email: "user@example.com"}

	s.T().Run("deletes sessions then user", func(t *testing.T) {
		gomock.InOrder(
			s.mockUserStore.EXPECT().FindByID(ctx, userID).Return(existingUser, nil),
			s.mockSessionStore.EXPECT().DeleteSessionsByUser(ctx, userID).Return(nil),
			s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil),
			s.mockUserStore.EXPECT().Delete(ctx, userID).Return(nil),
			s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil),
		)

		err := s.service.DeleteUser(ctx, userID)
		assert.NoError(t, err)
	})

	s.T().Run("no sessions found still deletes user", func(t *testing.T) {
		gomock.InOrder(
			s.mockUserStore.EXPECT().FindByID(ctx, userID).Return(existingUser, nil),
			s.mockSessionStore.EXPECT().DeleteSessionsByUser(ctx, userID).Return(sessionStore.ErrNotFound),
			s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil), // sessions_revoked event
			s.mockUserStore.EXPECT().Delete(ctx, userID).Return(nil),
			s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil), // user_deleted event
		)

		err := s.service.DeleteUser(ctx, userID)
		assert.NoError(t, err)
	})

	s.T().Run("user lookup fails", func(t *testing.T) {
		s.mockUserStore.EXPECT().FindByID(ctx, userID).Return(nil, errors.New("db down"))

		err := s.service.DeleteUser(ctx, userID)
		require.Error(t, err)
		assert.True(t, dErrors.Is(err, dErrors.CodeInternal))
	})

	s.T().Run("user not found", func(t *testing.T) {
		s.mockUserStore.EXPECT().FindByID(ctx, userID).Return(nil, userStore.ErrNotFound)

		err := s.service.DeleteUser(ctx, userID)
		require.Error(t, err)
		assert.True(t, dErrors.Is(err, dErrors.CodeNotFound))
	})

	s.T().Run("session delete fails", func(t *testing.T) {
		gomock.InOrder(
			s.mockUserStore.EXPECT().FindByID(ctx, userID).Return(existingUser, nil),
			s.mockSessionStore.EXPECT().DeleteSessionsByUser(ctx, userID).Return(errors.New("redis down")),
		)

		err := s.service.DeleteUser(ctx, userID)
		require.Error(t, err)
		assert.True(t, dErrors.Is(err, dErrors.CodeInternal))
	})

	s.T().Run("user delete fails", func(t *testing.T) {
		gomock.InOrder(
			s.mockUserStore.EXPECT().FindByID(ctx, userID).Return(existingUser, nil),
			s.mockSessionStore.EXPECT().DeleteSessionsByUser(ctx, userID).Return(nil),
			s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil),
			s.mockUserStore.EXPECT().Delete(ctx, userID).Return(errors.New("write fail")),
		)

		err := s.service.DeleteUser(ctx, userID)
		require.Error(t, err)
		assert.True(t, dErrors.Is(err, dErrors.CodeInternal))
	})
}
