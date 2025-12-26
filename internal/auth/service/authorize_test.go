package service

import (
	"context"
	"testing"

	authdevice "credo/internal/auth/device"
	"credo/internal/auth/models"
	tenant "credo/internal/tenant/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	devicemw "credo/pkg/platform/middleware/device"
	metadata "credo/pkg/platform/middleware/metadata"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// TestAuthorize tests the OAuth 2.0 authorization code flow
//
// These unit tests verify behaviors NOT covered by Gherkin:
// - Device binding with fingerprint hashing (needs device setup not available in e2e)
// - Input validation error mapping (fast feedback)
// - Store error propagation to domain errors
func (s *ServiceSuite) TestAuthorize() {
	tenantID := id.TenantID(uuid.New())
	clientID := id.ClientID(uuid.New())

	mockClient := &tenant.Client{
		ID:            clientID,
		TenantID:      tenantID,
		OAuthClientID: "client-123",
		Name:          "Test Client",
		Status:        "active",
		RedirectURIs:  []string{"https://client.app/callback"},
	}

	mockTenant := &tenant.Tenant{
		ID:   tenantID,
		Name: "Test Tenant",
	}

	var existingUser = &models.User{
		ID:        id.UserID(uuid.New()),
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

	s.T().Run("device binding enabled attaches device metadata", func(t *testing.T) {
		// Temporarily enable device binding on the service
		prevBinding := s.service.DeviceBindingEnabled
		prevDeviceSvc := s.service.deviceService
		s.service.DeviceBindingEnabled = true
		deviceSvc := authdevice.NewService(true)
		s.service.deviceService = deviceSvc
		t.Cleanup(func() {
			s.service.DeviceBindingEnabled = prevBinding
			s.service.deviceService = prevDeviceSvc
		})

		req := baseReq
		req.State = "xyz"
		userAgent := "Mozilla/5.0"
		ctx := metadata.WithClientMetadata(context.Background(), "192.168.1.1", userAgent)
		// Inject pre-computed fingerprint (as Device middleware would)
		ctx = devicemw.WithDeviceFingerprint(ctx, deviceSvc.ComputeFingerprint(userAgent))

		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), req.ClientID).Return(mockClient, mockTenant, nil)

		s.mockUserStore.EXPECT().FindOrCreateByTenantAndEmail(gomock.Any(), tenantID, req.Email, gomock.Any()).DoAndReturn(
			func(ctx context.Context, tid id.TenantID, email string, user *models.User) (*models.User, error) {
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
		s.NoError(err)
		s.NotEmpty(result.DeviceID)
	})

	s.T().Run("invalid redirect_uri scheme rejected", func(t *testing.T) {
		req := baseReq
		req.RedirectURI = "ftp://client.app/callback" // Invalid scheme

		result, err := s.service.Authorize(context.Background(), &req)
		s.Error(err)
		s.Nil(result)
		s.True(dErrors.HasCode(err, dErrors.CodeBadRequest))
		s.Contains(err.Error(), "redirect_uri scheme")
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
		s.Error(err)
		s.Nil(result)
	})
}

// TestAuthorizeClientValidation tests that authorize rejects requests
// when the client is inactive (PRD-026A FR-4.5.3).

func (s *ServiceSuite) TestAuthorizeClientValidation() {
	s.T().Run("inactive client rejected", func(t *testing.T) {
		req := models.AuthorizationRequest{
			ClientID:    "inactive-client",
			Scopes:      []string{"openid"},
			RedirectURI: "https://app.example.com/callback",
			Email:       "user@test.com",
		}
		ctx := context.Background()

		// Client resolver returns invalid_client for inactive client
		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), req.ClientID).
			Return(nil, nil, dErrors.New(dErrors.CodeInvalidClient, "client is inactive"))

		result, err := s.service.Authorize(ctx, &req)

		// PRD-026A FR-4.5.3: inactive client returns invalid_client
		s.Error(err, "expected error when client is inactive")
		s.Nil(result)
		s.True(dErrors.HasCode(err, dErrors.CodeInvalidClient),
			"expected invalid_client error code")
	})
}
