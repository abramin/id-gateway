package service

//go:generate mockgen -source=interfaces.go -destination=mocks/mocks.go -package=mocks UserStore,SessionStore,AuthCodeStore,RefreshTokenStore,TokenGenerator,AuditPublisher

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"credo/internal/auth/service/mocks"

	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
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
	)
}

func (s *ServiceSuite) TearDownTest() {
	s.ctrl.Finish()
}

func TestServiceSuite(t *testing.T) {
	suite.Run(t, new(ServiceSuite))
}
