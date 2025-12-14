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

// TestUserInfo tests the OIDC userinfo endpoint (PRD-001 FR-3)
func (s *ServiceSuite) TestUserInfo() {
	existingUser := &models.User{
		ID:        uuid.New(),
		Email:     "user@example.com",
		FirstName: "John",
		LastName:  "Doe",
		Verified:  true,
	}

	s.T().Run("happy path - returns user info", func(t *testing.T) {
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(&models.Session{
			UserID: existingUser.ID,
			Status: string(models.SessionStatusActive),
		}, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), existingUser.ID).Return(existingUser, nil)
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		result, err := s.service.UserInfo(context.Background(), uuid.New().String())
		require.NoError(s.T(), err)
		assert.Equal(s.T(), existingUser.ID.String(), result.Sub)
		assert.Equal(s.T(), existingUser.Email, result.Email)
		assert.Equal(s.T(), existingUser.Verified, result.EmailVerified)
		assert.Equal(s.T(), existingUser.FirstName, result.GivenName)
		assert.Equal(s.T(), existingUser.LastName, result.FamilyName)
		assert.Equal(s.T(), "John Doe", result.Name)
	})

	s.T().Run("session lookup returns not found error", func(t *testing.T) {
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(nil, sessionStore.ErrNotFound)

		result, err := s.service.UserInfo(context.Background(), uuid.New().String())
		assert.ErrorIs(s.T(), err, dErrors.New(dErrors.CodeUnauthorized, "session not found"))
		assert.Nil(s.T(), result)
	})

	s.T().Run("user not found", func(t *testing.T) {
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(&models.Session{
			UserID: existingUser.ID,
			Status: string(models.SessionStatusActive),
		}, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), existingUser.ID).Return(nil, userStore.ErrNotFound)

		result, err := s.service.UserInfo(context.Background(), uuid.New().String())
		assert.ErrorIs(s.T(), err, dErrors.New(dErrors.CodeUnauthorized, "user not found"))
		assert.Nil(s.T(), result)
	})

	s.T().Run("session not active", func(t *testing.T) {
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(&models.Session{
			Status: string(models.SessionStatusPendingConsent),
		}, nil)

		result, err := s.service.UserInfo(context.Background(), uuid.New().String())
		assert.ErrorIs(s.T(), err, dErrors.New(dErrors.CodeUnauthorized, "session not active"))
		assert.Nil(s.T(), result)
	})

	s.T().Run("session store error", func(t *testing.T) {
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(nil, assert.AnError)

		result, err := s.service.UserInfo(context.Background(), uuid.New().String())
		assert.Error(s.T(), err)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeInternal))
		assert.Nil(s.T(), result)
	})

	s.T().Run("user store error", func(t *testing.T) {
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(&models.Session{
			UserID: existingUser.ID,
			Status: string(models.SessionStatusActive),
		}, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), existingUser.ID).Return(nil, errors.New("db error"))

		result, err := s.service.UserInfo(context.Background(), uuid.New().String())
		assert.Error(s.T(), err)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeInternal))
		assert.Nil(s.T(), result)
	})

	s.T().Run("missing session identifier", func(t *testing.T) {
		result, err := s.service.UserInfo(context.Background(), "")
		assert.ErrorIs(s.T(), err, dErrors.New(dErrors.CodeUnauthorized, "missing or invalid session"))
		assert.Nil(s.T(), result)
	})

	s.T().Run("invalid session identifier", func(t *testing.T) {
		result, err := s.service.UserInfo(context.Background(), "invalid-uuid")
		assert.ErrorIs(s.T(), err, dErrors.New(dErrors.CodeUnauthorized, "invalid session ID"))
		assert.Nil(s.T(), result)
	})
}
