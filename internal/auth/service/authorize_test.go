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
		ID:           clientID,
		TenantID:     tenantID,
		ClientID:     "client-123",
		Name:         "Test Client",
		Status:       "active",
		RedirectURIs: []string{"https://client.app/callback"},
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
		deviceSvc := device.NewService(true)
		s.service.deviceService = deviceSvc
		t.Cleanup(func() {
			s.service.DeviceBindingEnabled = prevBinding
			s.service.deviceService = prevDeviceSvc
		})

		req := baseReq
		req.State = "xyz"
		userAgent := "Mozilla/5.0"
		ctx := middleware.WithClientMetadata(context.Background(), "192.168.1.1", userAgent)
		// Inject pre-computed fingerprint (as Device middleware would)
		ctx = middleware.WithDeviceFingerprint(ctx, deviceSvc.ComputeFingerprint(userAgent))

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

// TestAuthorizeClientValidation tests that authorize rejects requests
// when the client is unknown or inactive (RFC 6749 §4.1.2.1 and PRD-026A FR-4.5.3).
func (s *ServiceSuite) TestAuthorizeClientValidation() {
	s.T().Run("unknown client_id rejected (RFC 6749 §4.1.2.1)", func(t *testing.T) {
		req := models.AuthorizationRequest{
			ClientID:    "unknown-client",
			Scopes:      []string{"openid"},
			RedirectURI: "https://app.example.com/callback",
			Email:       "user@test.com",
		}
		ctx := context.Background()

		// Client resolver returns not_found for unknown client
		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), req.ClientID).
			Return(nil, nil, dErrors.New(dErrors.CodeInvalidClient, "client not found"))

		result, err := s.service.Authorize(ctx, &req)

		// RFC 6749 §4.1.2.1: If client_id is missing or invalid, MUST NOT redirect
		// Returns 400 Bad Request with invalid_client error
		assert.Error(t, err, "expected error when client_id is unknown")
		assert.Nil(t, result)
		assert.True(t, dErrors.Is(err, dErrors.CodeInvalidClient),
			"expected invalid_client error code per RFC 6749")
	})

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
		assert.Error(t, err, "expected error when client is inactive")
		assert.Nil(t, result)
		assert.True(t, dErrors.Is(err, dErrors.CodeInvalidClient),
			"expected invalid_client error code")
	})
}

// TestAuthorizeRedirectURIValidation tests that authorize rejects redirect URIs
// not registered on the client (PRD-026A FR-8).
// This test is expected to FAIL until the validation is implemented.
func (s *ServiceSuite) TestAuthorizeRedirectURIValidation() {
	tenantID := uuid.New()
	clientID := uuid.New()

	// Client with specific registered redirect URIs
	mockClient := &tenant.Client{
		ID:           clientID,
		TenantID:     tenantID,
		ClientID:     "client-123",
		Name:         "Test Client",
		Status:       "active",
		RedirectURIs: []string{"https://allowed.example.com/callback"},
	}

	mockTenant := &tenant.Tenant{
		ID:   tenantID,
		Name: "Test Tenant",
	}

	s.T().Run("redirect_uri not in client.RedirectURIs rejected", func(t *testing.T) {
		req := models.AuthorizationRequest{
			ClientID:    "client-123",
			Scopes:      []string{"openid"},
			RedirectURI: "https://attacker.example.com/callback", // Not in client's registered URIs
			Email:       "user@test.com",
		}
		ctx := context.Background()

		// Auth should resolve client to get redirect_uris
		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), req.ClientID).Return(mockClient, mockTenant, nil)

		// Expect failure BEFORE user lookup - redirect_uri validation should happen early
		result, err := s.service.Authorize(ctx, &req)

		// This test documents the expected behavior per PRD-026A FR-8:
		// "Redirect URI Matching: Exact match against registered URIs"
		assert.Error(t, err, "expected error when redirect_uri is not in client.RedirectURIs")
		assert.Nil(t, result)
		assert.True(t, dErrors.Is(err, dErrors.CodeBadRequest), "expected bad_request error code")
		assert.Contains(t, err.Error(), "redirect_uri", "error message should mention redirect_uri")
	})

	s.T().Run("redirect_uri in client.RedirectURIs accepted", func(t *testing.T) {
		req := models.AuthorizationRequest{
			ClientID:    "client-123",
			Scopes:      []string{"openid"},
			RedirectURI: "https://allowed.example.com/callback", // In client's registered URIs
			Email:       "user@test.com",
		}
		ctx := context.Background()

		existingUser := &models.User{
			ID:       uuid.New(),
			TenantID: tenantID,
			Email:    req.Email,
			Status:   models.UserStatusActive,
		}

		s.mockClientResolver.EXPECT().ResolveClient(gomock.Any(), req.ClientID).Return(mockClient, mockTenant, nil)
		s.mockUserStore.EXPECT().FindOrCreateByTenantAndEmail(gomock.Any(), tenantID, req.Email, gomock.Any()).Return(existingUser, nil)
		s.mockCodeStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
		s.mockSessionStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		result, err := s.service.Authorize(ctx, &req)
		assert.NoError(t, err, "expected success when redirect_uri is in client.RedirectURIs")
		assert.NotNil(t, result)
	})
}

