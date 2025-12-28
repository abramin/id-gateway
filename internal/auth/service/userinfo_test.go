package service

import (
	"context"
	"errors"

	"credo/internal/auth/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/sentinel"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// TestUserInfo_ErrorAndValidationHandling tests the OIDC userinfo endpoint (PRD-001 FR-3)
//
// AGENTS.MD JUSTIFICATION (per testing.md doctrine):
// These unit tests verify behaviors NOT covered by Gherkin:
// - session not found: Tests error propagation from session store
// - user not found: Tests error propagation from user store
// - session not active: Tests edge case (pending_consent status)
// - store errors: Tests CodeInternal error mapping
// - validation: Tests input validation error codes
func (s *ServiceSuite) TestUserInfo_ErrorAndValidationHandling() {
	existingUser := &models.User{
		ID:        id.UserID(uuid.New()),
		Email:     "user@example.com",
		FirstName: "John",
		LastName:  "Doe",
		Verified:  true,
	}

	s.Run("session lookup returns not found error", func() {
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(nil, sentinel.ErrNotFound)
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		result, err := s.service.UserInfo(context.Background(), uuid.New().String())
		s.Require().ErrorIs(err, dErrors.New(dErrors.CodeUnauthorized, "session not found"))
		s.Nil(result)
	})

	s.Run("user not found", func() {
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(&models.Session{
			UserID: existingUser.ID,
			Status: models.SessionStatusActive,
		}, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), existingUser.ID).Return(nil, sentinel.ErrNotFound)
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		result, err := s.service.UserInfo(context.Background(), uuid.New().String())
		s.Require().ErrorIs(err, dErrors.New(dErrors.CodeUnauthorized, "user not found"))
		s.Nil(result)
	})

	s.Run("session not active", func() {
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(&models.Session{
			Status: models.SessionStatusPendingConsent,
		}, nil)
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		result, err := s.service.UserInfo(context.Background(), uuid.New().String())
		s.Require().ErrorIs(err, dErrors.New(dErrors.CodeUnauthorized, "session not active"))
		s.Nil(result)
	})

	s.Run("session store error", func() {
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(nil, assert.AnError)
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		result, err := s.service.UserInfo(context.Background(), uuid.New().String())
		s.Require().Error(err)
		s.True(dErrors.HasCode(err, dErrors.CodeInternal))
		s.Nil(result)
	})

	s.Run("user store error", func() {
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(&models.Session{
			UserID: existingUser.ID,
			Status: models.SessionStatusActive,
		}, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), existingUser.ID).Return(nil, errors.New("db error"))
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		result, err := s.service.UserInfo(context.Background(), uuid.New().String())
		s.Require().Error(err)
		s.True(dErrors.HasCode(err, dErrors.CodeInternal))
		s.Nil(result)
	})

	s.Run("missing session identifier", func() {
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		result, err := s.service.UserInfo(context.Background(), "")
		s.Require().ErrorIs(err, dErrors.New(dErrors.CodeUnauthorized, "missing or invalid session"))
		s.Nil(result)
	})

	s.Run("invalid session identifier", func() {
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		result, err := s.service.UserInfo(context.Background(), "invalid-uuid")
		s.Require().ErrorIs(err, dErrors.New(dErrors.CodeUnauthorized, "invalid session ID"))
		s.Nil(result)
	})
}
