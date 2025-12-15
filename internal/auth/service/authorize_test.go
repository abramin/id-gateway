package service

import (
	"context"
	"testing"
	"time"

	"credo/internal/auth/device"
	"credo/internal/auth/models"
	"credo/internal/platform/middleware"
	tenant "credo/internal/tenant/models"
	dErrors "credo/pkg/domain-errors"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// TestAuthorize tests the OAuth 2.0 authorization code flow (PRD-001 FR-1)
func (s *ServiceSuite) TestAuthorize() {
	tenantID := uuid.New()
	clientID := uuid.New()

	mockClient := &tenant.Client{
		ID:       clientID,
		TenantID: tenantID,
		ClientID: "client-123",
		Name:     "Test Client",
		Status:   "active",
	}

	mockTenant := &tenant.Tenant{
		ID:   tenantID,
		Name: "Test Tenant",
	}

	var existingUser = &models.User{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Email:     "email@test.com",
		FirstName: "Existing",
		LastName:  "User",
		Verified:  true,
		Status:    models.UserStatusActive,
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

		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), req.ClientID).Return(mockClient, mockTenant, nil)

		s.mockUserStore.EXPECT().FindOrCreateByTenantAndEmail(gomock.Any(), tenantID, req.Email, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tid uuid.UUID, email string, user *models.User) (*models.User, error) {
				assert.Equal(s.T(), tenantID, tid)
				assert.Equal(s.T(), req.Email, email)
				assert.Equal(s.T(), req.Email, user.Email)
				assert.Equal(s.T(), tenantID, user.TenantID)
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
				assert.Equal(s.T(), clientID, session.ClientID)
				assert.Equal(s.T(), tenantID, session.TenantID)
				assert.True(s.T(), session.ExpiresAt.After(time.Now()))
				assert.Equal(s.T(), string(models.SessionStatusPendingConsent), session.Status)
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

		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), req.ClientID).Return(mockClient, mockTenant, nil)
		s.mockUserStore.EXPECT().FindOrCreateByTenantAndEmail(gomock.Any(), tenantID, req.Email, gomock.Any()).Return(existingUser, nil)
		s.mockCodeStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
		s.mockSessionStore.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, session *models.Session) error {
				assert.Equal(s.T(), existingUser.ID, session.UserID)
				assert.Equal(s.T(), clientID, session.ClientID)
				assert.Equal(s.T(), tenantID, session.TenantID)
				assert.True(s.T(), session.ExpiresAt.After(time.Now()))
				assert.Equal(s.T(), string(models.SessionStatusPendingConsent), session.Status)
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
		// Temporarily enable device binding on the service
		prevBinding := s.service.DeviceBindingEnabled
		prevDeviceSvc := s.service.deviceService
		s.service.DeviceBindingEnabled = true
		s.service.deviceService = device.NewService(true)
		t.Cleanup(func() {
			s.service.DeviceBindingEnabled = prevBinding
			s.service.deviceService = prevDeviceSvc
		})

		req := baseReq
		req.State = "xyz"
		ctx := middleware.WithClientMetadata(context.Background(), "192.168.1.1", "Mozilla/5.0")

		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), req.ClientID).Return(mockClient, mockTenant, nil)

		s.mockUserStore.EXPECT().FindOrCreateByTenantAndEmail(gomock.Any(), tenantID, req.Email, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tid uuid.UUID, email string, user *models.User) (*models.User, error) {
				return user, nil
			})

		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		s.mockCodeStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)

		s.mockSessionStore.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, session *models.Session) error {
				assert.NotEmpty(s.T(), session.DeviceID)
				assert.NotEmpty(s.T(), session.DeviceFingerprintHash)
				assert.Equal(s.T(), clientID, session.ClientID)
				assert.Equal(s.T(), tenantID, session.TenantID)
				return nil
			})

		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		result, err := s.service.Authorize(ctx, &req)
		assert.NoError(s.T(), err)
		assert.NotEmpty(s.T(), result.DeviceID)
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

		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), req.ClientID).Return(mockClient, mockTenant, nil)
		s.mockUserStore.EXPECT().FindOrCreateByTenantAndEmail(gomock.Any(), tenantID, req.Email, gomock.Any()).Return(nil, assert.AnError)

		result, err := s.service.Authorize(ctx, &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
	})

	s.T().Run("session store error", func(t *testing.T) {
		req := baseReq
		ctx := context.Background()

		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), req.ClientID).Return(mockClient, mockTenant, nil)
		s.mockUserStore.EXPECT().FindOrCreateByTenantAndEmail(gomock.Any(), tenantID, req.Email, gomock.Any()).Return(existingUser, nil)
		s.mockCodeStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
		s.mockSessionStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return(assert.AnError)

		result, err := s.service.Authorize(ctx, &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
	})
}
