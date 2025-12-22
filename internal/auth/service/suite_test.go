package service

//go:generate mockgen -source=service.go -destination=mocks/mocks.go -package=mocks UserStore,SessionStore,AuthCodeStore,RefreshTokenStore,TokenGenerator,AuditPublisher
//go:generate mockgen -source=../store/revocation/revocation.go -destination=mocks/trl_mock.go -package=mocks TokenRevocationList

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	"credo/internal/auth/models"
	"credo/internal/auth/service/mocks"
	tenant "credo/internal/tenant/models"
	id "credo/pkg/domain"
)

type ServiceSuite struct {
	suite.Suite
	ctrl               *gomock.Controller
	mockUserStore      *mocks.MockUserStore
	mockSessionStore   *mocks.MockSessionStore
	mockCodeStore      *mocks.MockAuthCodeStore
	mockRefreshStore   *mocks.MockRefreshTokenStore
	mockJWT            *mocks.MockTokenGenerator
	mockAuditPublisher *mocks.MockAuditPublisher
	mockTRL            *mocks.MockTokenRevocationList
	mockClientResolver *mocks.MockClientResolver
	service            *Service
}

func (s *ServiceSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.mockUserStore = mocks.NewMockUserStore(s.ctrl)
	s.mockSessionStore = mocks.NewMockSessionStore(s.ctrl)
	s.mockCodeStore = mocks.NewMockAuthCodeStore(s.ctrl)
	s.mockRefreshStore = mocks.NewMockRefreshTokenStore(s.ctrl)
	s.mockJWT = mocks.NewMockTokenGenerator(s.ctrl)
	s.mockAuditPublisher = mocks.NewMockAuditPublisher(s.ctrl)
	s.mockTRL = mocks.NewMockTokenRevocationList(s.ctrl)
	s.mockClientResolver = mocks.NewMockClientResolver(s.ctrl)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &Config{
		SessionTTL:             2 * time.Hour,
		TokenTTL:               30 * time.Minute,
		RefreshTokenTTL:        1 * time.Hour,
		AllowedRedirectSchemes: []string{"https", "http"},
		DeviceBindingEnabled:   false, // default tests don't require device metadata
	}
	s.service, _ = New(
		s.mockUserStore,
		s.mockSessionStore,
		s.mockCodeStore,
		s.mockRefreshStore,
		cfg,
		WithLogger(logger),
		WithJWTService(s.mockJWT),
		WithAuditPublisher(s.mockAuditPublisher),
		WithTRL(s.mockTRL),
		WithClientResolver(s.mockClientResolver),
	)
}

func (s *ServiceSuite) TearDownTest() {
	s.ctrl.Finish()
}

func TestServiceSuite(t *testing.T) {
	suite.Run(t, new(ServiceSuite))
}

// Shared test fixture builders - used across multiple test files

func (s *ServiceSuite) newTestClient(tenantID id.TenantID, clientUUID id.ClientID) (*tenant.Client, *tenant.Tenant) {
	return &tenant.Client{
			ID:             clientUUID,
			TenantID:       tenantID,
			OAuthClientID:  "client-123",
			Name:           "Test Client",
			Status:         "active",
		}, &tenant.Tenant{
			ID:   tenantID,
			Name: "Test Tenant",
		}
}

func (s *ServiceSuite) newTestUser(userID id.UserID, tenantID id.TenantID) *models.User {
	return &models.User{
		ID:        userID,
		TenantID:  tenantID,
		Email:     "user@test.com",
		FirstName: "Test",
		LastName:  "User",
		Status:    models.UserStatusActive,
	}
}

func (s *ServiceSuite) newTestSession(sessionID id.SessionID, userID id.UserID, clientUUID id.ClientID, tenantID id.TenantID) *models.Session {
	return &models.Session{
		ID:             sessionID,
		UserID:         userID,
		ClientID:       clientUUID,
		TenantID:       tenantID,
		RequestedScope: []string{"openid", "profile"},
		DeviceID:       "device-123",
		Status:         models.SessionStatusActive,
		CreatedAt:      time.Now().Add(-1 * time.Hour),
		ExpiresAt:      time.Now().Add(23 * time.Hour),
	}
}

// expectTokenGeneration sets up JWT mock expectations for token generation.
// Returns the mock token values that will be returned by the mocks.
func (s *ServiceSuite) expectTokenGeneration(userID id.UserID, sessionID id.SessionID, clientUUID id.ClientID, tenantID id.TenantID, scopes []string) (accessToken, accessTokenJTI, idToken, refreshToken string) {
	accessToken = "mock-access-token"
	accessTokenJTI = "mock-access-token-jti"
	idToken = "mock-id-token"
	refreshToken = "ref_mock-refresh-token"

	s.mockJWT.EXPECT().GenerateAccessTokenWithJTI(
		uuid.UUID(userID), uuid.UUID(sessionID), clientUUID.String(), tenantID.String(), scopes,
	).Return(accessToken, accessTokenJTI, nil)
	s.mockJWT.EXPECT().GenerateIDToken(uuid.UUID(userID), uuid.UUID(sessionID), clientUUID.String(), tenantID.String()).Return(idToken, nil)
	s.mockJWT.EXPECT().CreateRefreshToken().Return(refreshToken, nil)

	return
}
