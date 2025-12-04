package service

//go:generate mockgen -source=service.go -destination=mocks/mocks.go -package=mocks UserStore,SessionStoreimport
import (
	"context"
	"id-gateway/internal/auth/models"
	"id-gateway/internal/auth/service/mocks"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type ServiceSuite struct {
	suite.Suite
	ctrl          *gomock.Controller
	mockUserStore *mocks.MockUserStore
	mockSessStore *mocks.MockSessionStore
	service       *Service
}

func (s *ServiceSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.mockUserStore = mocks.NewMockUserStore(s.ctrl)
	s.mockSessStore = mocks.NewMockSessionStore(s.ctrl)
	s.service = NewService(s.mockUserStore, s.mockSessStore, 15*time.Minute)
}

func (s *ServiceSuite) TearDownTest() {
	s.ctrl.Finish()
}

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

		s.mockUserStore.EXPECT().FindByEmail(gomock.Any(), req.Email).Return(nil, models.ErrUserNotFound)
		s.mockUserStore.EXPECT().Save(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, user *models.User) error {
			assert.Equal(s.T(), req.Email, user.Email)
			assert.Equal(s.T(), "Email", user.FirstName)
			assert.Equal(s.T(), "User", user.LastName)
			assert.False(s.T(), user.Verified)
			assert.NotNil(s.T(), user.ID)
			return nil
		})
		s.mockSessStore.EXPECT().Save(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, session models.Session) error {
				assert.NotNil(s.T(), session.UserID)
				assert.True(s.T(), session.ExpiresAt.After(time.Now()))
				assert.Equal(s.T(), StatusPendingConsent, session.Status)
				assert.NotNil(s.T(), session.ID)
				return nil
			})

		result, err := s.service.Authorize(context.Background(), &req)
		assert.NoError(s.T(), err)
		assert.NotEmpty(s.T(), result.SessionID)
		assert.Contains(s.T(), result.RedirectURI, "https://client.app/callback")
		assert.Contains(s.T(), result.RedirectURI, "session_id="+result.SessionID.String())
		assert.Contains(s.T(), result.RedirectURI, "state=xyz")
	})

	s.T().Run("happy path - user exists", func(t *testing.T) {
		req := baseReq

		s.mockUserStore.EXPECT().FindByEmail(gomock.Any(), req.Email).Return(existingUser, nil)
		s.mockSessStore.EXPECT().Save(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, session models.Session) error {
				assert.Equal(s.T(), existingUser.ID, session.UserID)
				assert.True(s.T(), session.ExpiresAt.After(time.Now()))
				assert.Equal(s.T(), StatusPendingConsent, session.Status)
				assert.NotNil(s.T(), session.ID)
				return nil
			})

		result, err := s.service.Authorize(context.Background(), &req)
		assert.NoError(s.T(), err)
		assert.NotEmpty(s.T(), result.SessionID)
		assert.Contains(s.T(), result.RedirectURI, "https://client.app/callback")
		assert.Contains(s.T(), result.RedirectURI, "session_id="+result.SessionID.String())
	})

	s.T().Run("user store error", func(t *testing.T) {
		req := baseReq
		s.mockUserStore.EXPECT().FindByEmail(gomock.Any(), req.Email).Return(nil, assert.AnError)

		result, err := s.service.Authorize(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
	})

	s.T().Run("session store error", func(t *testing.T) {
		req := models.AuthorizationRequest{
			ClientID:    "client-123",
			Scopes:      []string{"openid", "profile"},
			RedirectURI: "https://client.app/callback",
			Email:       "email@test.com",
		}

		s.mockUserStore.EXPECT().FindByEmail(gomock.Any(), req.Email).Return(existingUser, nil)
		s.mockSessStore.EXPECT().Save(gomock.Any(), gomock.Any()).Return(assert.AnError)

		result, err := s.service.Authorize(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
	})
}
func TestServiceSuite(t *testing.T) {
	suite.Run(t, new(ServiceSuite))
}
