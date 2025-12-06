package service

//go:generate mockgen -source=service.go -destination=mocks/mocks.go -package=mocks UserStore,SessionStore,TokenGenerator

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"id-gateway/internal/auth/models"
	"id-gateway/internal/auth/service/mocks"
	"id-gateway/internal/auth/store"
	dErrors "id-gateway/pkg/domain-errors"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type ServiceSuite struct {
	suite.Suite
	ctrl          *gomock.Controller
	mockUserStore *mocks.MockUserStore
	mockSessStore *mocks.MockSessionStore
	mockJWT       *mocks.MockTokenGenerator
	service       *Service
}

func (s *ServiceSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.mockUserStore = mocks.NewMockUserStore(s.ctrl)
	s.mockSessStore = mocks.NewMockSessionStore(s.ctrl)
	s.mockJWT = mocks.NewMockTokenGenerator(s.ctrl)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s.service = NewService(s.mockUserStore, s.mockSessStore, 15*time.Minute,
		WithLogger(logger),
		WithJWTService(s.mockJWT))
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

		s.mockUserStore.EXPECT().FindOrCreateByEmail(gomock.Any(), req.Email, gomock.Any()).DoAndReturn(func(ctx context.Context, email string, user *models.User) (*models.User, error) {
			assert.Equal(s.T(), req.Email, email)
			assert.Equal(s.T(), req.Email, user.Email)
			assert.Equal(s.T(), "Email", user.FirstName)
			assert.Equal(s.T(), "User", user.LastName)
			assert.False(s.T(), user.Verified)
			assert.NotNil(s.T(), user.ID)
			return user, nil
		})
		s.mockSessStore.EXPECT().Save(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, session *models.Session) error {
				assert.NotNil(s.T(), session.UserID)
				assert.True(s.T(), session.ExpiresAt.After(time.Now()))
				assert.Equal(s.T(), StatusPendingConsent, session.Status)
				assert.NotNil(s.T(), session.ID)
				return nil
			})

		result, err := s.service.Authorize(context.Background(), &req)
		assert.NoError(s.T(), err)
		assert.NotEmpty(s.T(), result.Code)
		assert.Contains(s.T(), result.Code, "authz_")
		assert.Contains(s.T(), result.RedirectURI, "https://client.app/callback")
		assert.Contains(s.T(), result.RedirectURI, "code="+result.Code)
		assert.Contains(s.T(), result.RedirectURI, "state=xyz")
	})

	s.T().Run("happy path - user exists", func(t *testing.T) {
		req := baseReq

		s.mockUserStore.EXPECT().FindOrCreateByEmail(gomock.Any(), req.Email, gomock.Any()).Return(existingUser, nil)
		s.mockSessStore.EXPECT().Save(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, session *models.Session) error {
				assert.Equal(s.T(), existingUser.ID, session.UserID)
				assert.True(s.T(), session.ExpiresAt.After(time.Now()))
				assert.Equal(s.T(), StatusPendingConsent, session.Status)
				assert.NotNil(s.T(), session.ID)
				return nil
			})

		result, err := s.service.Authorize(context.Background(), &req)
		assert.NoError(s.T(), err)
		assert.NotEmpty(s.T(), result.Code)
		assert.Contains(s.T(), result.Code, "authz_")
		assert.Contains(s.T(), result.RedirectURI, "https://client.app/callback")
		assert.Contains(s.T(), result.RedirectURI, "code="+result.Code)
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

func (s *ServiceSuite) TestToken() {
	req := models.TokenRequest{
		GrantType:   "authorization_code",
		Code:        "authz_12345",
		RedirectURI: "https://client.app/callback",
		ClientID:    "client-123",
	}

	validSession := &models.Session{
		ID:             uuid.New(),
		UserID:         uuid.New(),
		Code:           req.Code,
		CodeExpiresAt:  time.Now().Add(5 * time.Minute),
		CodeUsed:       false,
		ClientID:       req.ClientID,
		RedirectURI:    req.RedirectURI,
		RequestedScope: []string{"openid", "profile"},
		Status:         StatusActive,
		CreatedAt:      time.Now().Add(-5 * time.Minute),
		ExpiresAt:      time.Now().Add(10 * time.Minute),
	}

	s.T().Run("happy path - tokens returned", func(t *testing.T) {
		s.mockSessStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(validSession, nil)
		s.mockSessStore.EXPECT().Save(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, session *models.Session) error {
				assert.True(s.T(), session.CodeUsed)
				return nil
			})
		s.mockJWT.EXPECT().GenerateAccessToken(validSession.UserID, validSession.ID, validSession.ClientID).
			Return("mock-access-token", nil)
		s.mockJWT.EXPECT().GenerateIDToken(validSession.UserID, validSession.ID, validSession.ClientID).
			Return("mock-id-token", nil)
		result, err := s.service.Token(context.Background(), &req)
		require.NoError(s.T(), err)
		assert.Equal(s.T(), "mock-access-token", result.AccessToken)
		assert.Equal(s.T(), "mock-id-token", result.IDToken)
		assert.Greater(s.T(), result.ExpiresIn, int64(0))
	})

	s.T().Run("session not found", func(t *testing.T) {
		s.mockSessStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(nil, store.ErrNotFound)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
	})

	s.T().Run("session expired", func(t *testing.T) {
		expiredSession := *validSession
		expiredSession.CodeExpiresAt = time.Now().Add(-5 * time.Minute)

		s.mockSessStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&expiredSession, nil)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
	})

	s.T().Run("session already used", func(t *testing.T) {
		usedSession := *validSession
		usedSession.CodeUsed = true

		s.mockSessStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&usedSession, nil)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
	})
	s.T().Run("session store error", func(t *testing.T) {
		s.mockSessStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(nil, assert.AnError)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
	})
	s.T().Run("request redirect URI mismatch", func(t *testing.T) {
		sess := *validSession
		sess.RedirectURI = "https://other.app/callback"
		s.mockSessStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&sess, nil)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
	})

	s.T().Run("request client ID mismatch", func(t *testing.T) {
		sess := *validSession
		sess.ClientID = "other-client"
		s.mockSessStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&sess, nil)
		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
	})
}

func (s *ServiceSuite) TestUserInfo() {
	existingUser := &models.User{
		ID:        uuid.New(),
		Email:     "user@example.com",
		FirstName: "John",
		LastName:  "Doe",
		Verified:  true,
	}
	s.T().Run("happy path - returns user info", func(t *testing.T) {
		s.mockSessStore.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(&models.Session{
			UserID: existingUser.ID,
			Status: StatusActive,
		}, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), existingUser.ID).Return(existingUser, nil)

		result, err := s.service.UserInfo(context.Background(), uuid.New())
		require.NoError(s.T(), err)
		assert.Equal(s.T(), existingUser.ID.String(), result.Sub)
		assert.Equal(s.T(), existingUser.Email, result.Email)
		assert.Equal(s.T(), existingUser.Verified, result.EmailVerified)
		assert.Equal(s.T(), existingUser.FirstName, result.GivenName)
		assert.Equal(s.T(), existingUser.LastName, result.FamilyName)
		assert.Equal(s.T(), "John Doe", result.Name)
	})

	s.T().Run("session not found", func(t *testing.T) {
		s.mockSessStore.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(nil, store.ErrNotFound)

		result, err := s.service.UserInfo(context.Background(), uuid.New())
		assert.ErrorIs(s.T(), err, dErrors.New(dErrors.CodeUnauthorized, "session not found"))
		assert.Nil(s.T(), result)
	})

	s.T().Run("user not found", func(t *testing.T) {
		s.mockSessStore.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(&models.Session{
			UserID: existingUser.ID,
			Status: StatusActive,
		}, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), existingUser.ID).Return(nil, store.ErrNotFound)

		result, err := s.service.UserInfo(context.Background(), uuid.New())
		assert.ErrorIs(s.T(), err, dErrors.New(dErrors.CodeUnauthorized, "user not found"))
		assert.Nil(s.T(), result)
	})

	s.T().Run("session not active", func(t *testing.T) {
		s.mockSessStore.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(&models.Session{
			Status: StatusPendingConsent,
		}, nil)

		result, err := s.service.UserInfo(context.Background(), uuid.New())
		assert.ErrorIs(s.T(), err, dErrors.New(dErrors.CodeUnauthorized, "session not active"))
		assert.Nil(s.T(), result)
	})

	s.T().Run("session store error", func(t *testing.T) {
		s.mockSessStore.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(nil, assert.AnError)

		result, err := s.service.UserInfo(context.Background(), uuid.New())
		assert.ErrorIs(s.T(), err, dErrors.New(dErrors.CodeInternal, "failed to find session"))
		assert.Nil(s.T(), result)
	})

	s.T().Run("user store error", func(t *testing.T) {
		s.mockSessStore.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(&models.Session{
			UserID: existingUser.ID,
			Status: StatusActive,
		}, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), existingUser.ID).Return(nil, errors.New("db error"))

		result, err := s.service.UserInfo(context.Background(), uuid.New())
		assert.ErrorIs(s.T(), err, dErrors.New(dErrors.CodeInternal, "failed to find user"))
		assert.Nil(s.T(), result)
	})
}

func TestServiceSuite(t *testing.T) {
	suite.Run(t, new(ServiceSuite))
}
