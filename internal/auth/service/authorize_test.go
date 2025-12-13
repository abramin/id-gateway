package service

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"credo/internal/auth/models"
	"credo/internal/auth/service/mocks"
	"credo/internal/platform/middleware"
	dErrors "credo/pkg/domain-errors"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// TestAuthorize tests the OAuth 2.0 authorization code flow (PRD-001 FR-1)
func (s *ServiceSuite) TestAuthorize() {
	var existingUser = &models.User{
		ID:        uuid.New(),
		Email:     "email@test.com",
		FirstName: "Existing",
		LastName:  "User",
		Verified:  true,
	}

	var baseReq = models.AuthorizationRequest{
		ClientID:    "client-123",
		Scopes:      []string{"openid", "profile"},
		RedirectURI: "https://client.app/callback",
		Email:       "email@test.com",
	}

	s.T().Run("happy path - user not found, creates user and session", func(t *testing.T) {
		req := baseReq
		req.State = "xyz"

		ctx := context.Background()

		s.mockUserStore.EXPECT().FindOrCreateByEmail(gomock.Any(), req.Email, gomock.Any()).DoAndReturn(
			func(ctx context.Context, email string, user *models.User) (*models.User, error) {
				assert.Equal(s.T(), req.Email, email)
				assert.Equal(s.T(), req.Email, user.Email)
				assert.NotNil(s.T(), user.ID)
				return user, nil
			})

		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		// Expect authorization code to be created
		s.mockCodeStore.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, code *models.AuthorizationCodeRecord) error {
				assert.Contains(s.T(), code.Code, "authz_")
				assert.Equal(s.T(), req.RedirectURI, code.RedirectURI)
				assert.False(s.T(), code.Used)
				assert.True(s.T(), code.ExpiresAt.After(time.Now()))
				return nil
			})

		// Expect session to be created
		s.mockSessionStore.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, session *models.Session) error {
				assert.NotNil(s.T(), session.UserID)
				assert.True(s.T(), session.ExpiresAt.After(time.Now()))
				assert.Equal(s.T(), StatusPendingConsent, session.Status)
				assert.NotNil(s.T(), session.ID)
				// Device binding disabled by default; device metadata optional
				return nil
			})

		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		result, err := s.service.Authorize(ctx, &req)
		assert.NoError(s.T(), err)
		assert.NotEmpty(s.T(), result.Code)
		assert.Contains(s.T(), result.Code, "authz_")
		assert.Contains(s.T(), result.RedirectURI, "https://client.app/callback")
		assert.Contains(s.T(), result.RedirectURI, "code="+result.Code)
		assert.Contains(s.T(), result.RedirectURI, "state=xyz")
		// DeviceID may be empty when device binding is disabled
	})

	s.T().Run("happy path - user exists", func(t *testing.T) {
		req := baseReq
		ctx := context.Background()

		s.mockUserStore.EXPECT().FindOrCreateByEmail(gomock.Any(), req.Email, gomock.Any()).Return(existingUser, nil)
		s.mockCodeStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
		s.mockSessionStore.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, session *models.Session) error {
				assert.Equal(s.T(), existingUser.ID, session.UserID)
				assert.True(s.T(), session.ExpiresAt.After(time.Now()))
				assert.Equal(s.T(), StatusPendingConsent, session.Status)
				assert.NotNil(s.T(), session.ID)
				return nil
			})
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		result, err := s.service.Authorize(ctx, &req)
		assert.NoError(s.T(), err)
		assert.NotEmpty(s.T(), result.Code)
		assert.Contains(s.T(), result.Code, "authz_")
		assert.Contains(s.T(), result.RedirectURI, "https://client.app/callback")
		assert.Contains(s.T(), result.RedirectURI, "code="+result.Code)
	})

	s.T().Run("device binding enabled attaches device metadata", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockUserStore := mocks.NewMockUserStore(ctrl)
		mockSessionStore := mocks.NewMockSessionStore(ctrl)
		mockCodeStore := mocks.NewMockAuthCodeStore(ctrl)
		mockRefreshStore := mocks.NewMockRefreshTokenStore(ctrl)
		mockJWT := mocks.NewMockTokenGenerator(ctrl)
		mockAuditPublisher := mocks.NewMockAuditPublisher(ctrl)
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		cfg := &Config{
			SessionTTL:             2 * time.Hour,
			TokenTTL:               30 * time.Minute,
			RefreshTokenTTL:        1 * time.Hour,
			AllowedRedirectSchemes: []string{"https", "http"},
			DeviceBindingEnabled:   true,
		}

		serviceWithDevice, _ := New(
			mockUserStore,
			mockSessionStore,
			mockCodeStore,
			mockRefreshStore,
			cfg,
			WithLogger(logger),
			WithJWTService(mockJWT),
			WithAuditPublisher(mockAuditPublisher),
			WithDeviceBindingEnabled(true),
		)

		req := baseReq
		req.State = "xyz"
		ctx := middleware.WithClientMetadata(context.Background(), "192.168.1.1", "Mozilla/5.0")

		mockUserStore.EXPECT().FindOrCreateByEmail(gomock.Any(), req.Email, gomock.Any()).DoAndReturn(
			func(ctx context.Context, email string, user *models.User) (*models.User, error) {
				return user, nil
			})

		mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		mockCodeStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)

		mockSessionStore.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, session *models.Session) error {
				assert.NotEmpty(t, session.DeviceID)
				assert.NotEmpty(t, session.DeviceFingerprintHash)
				return nil
			})

		mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		result, err := serviceWithDevice.Authorize(ctx, &req)
		assert.NoError(t, err)
		assert.NotEmpty(t, result.DeviceID)
	})

	s.T().Run("invalid redirect_uri scheme rejected", func(t *testing.T) {
		req := baseReq
		req.RedirectURI = "ftp://client.app/callback" // Invalid scheme

		result, err := s.service.Authorize(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeBadRequest))
		assert.Contains(s.T(), err.Error(), "redirect_uri scheme")
	})

	s.T().Run("user store error", func(t *testing.T) {
		req := baseReq
		ctx := context.Background()

		s.mockUserStore.EXPECT().FindOrCreateByEmail(gomock.Any(), req.Email, gomock.Any()).Return(nil, assert.AnError)

		result, err := s.service.Authorize(ctx, &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
	})

	s.T().Run("session store error", func(t *testing.T) {
		req := baseReq
		ctx := context.Background()

		s.mockUserStore.EXPECT().FindOrCreateByEmail(gomock.Any(), req.Email, gomock.Any()).Return(existingUser, nil)
		s.mockCodeStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
		s.mockSessionStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return(assert.AnError)

		result, err := s.service.Authorize(ctx, &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
	})
}
