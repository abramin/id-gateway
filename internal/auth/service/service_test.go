package service

//go:generate mockgen -source=service.go -destination=mocks/mocks.go -package=mocks UserStore,SessionStore,AuthCodeStore,RefreshTokenStore,TokenGenerator,AuditPublisher

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"credo/internal/auth/models"
	"credo/internal/auth/service/mocks"
	sessionStore "credo/internal/auth/store/session"
	userStore "credo/internal/auth/store/user"
	"credo/internal/platform/middleware"
	dErrors "credo/pkg/domain-errors"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	cfg := Config{
		SessionTTL:             2 * time.Hour,
		TokenTTL:               30 * time.Minute,
		AllowedRedirectSchemes: []string{"https", "http"},
		DeviceBindingEnabled:   true,
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

		ctx := middleware.WithClientMetadata(context.Background(), "192.168.1.1", "Mozilla/5.0")

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
				assert.NotEmpty(s.T(), session.DeviceID)
				assert.NotEmpty(s.T(), session.DeviceFingerprintHash)
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
		assert.NotEmpty(s.T(), result.DeviceID)
	})

	s.T().Run("happy path - user exists", func(t *testing.T) {
		req := baseReq
		ctx := middleware.WithClientMetadata(context.Background(), "192.168.1.1", "Mozilla/5.0")

		s.mockUserStore.EXPECT().FindOrCreateByEmail(gomock.Any(), req.Email, gomock.Any()).Return(existingUser, nil)
		s.mockCodeStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
		s.mockSessionStore.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, session *models.Session) error {
				assert.Equal(s.T(), existingUser.ID, session.UserID)
				assert.True(s.T(), session.ExpiresAt.After(time.Now()))
				assert.Equal(s.T(), StatusPendingConsent, session.Status)
				assert.NotNil(s.T(), session.ID)
				assert.NotEmpty(s.T(), session.DeviceID)
				return nil
			})
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		result, err := s.service.Authorize(ctx, &req)
		assert.NoError(s.T(), err)
		assert.NotEmpty(s.T(), result.Code)
		assert.Contains(s.T(), result.Code, "authz_")
		assert.Contains(s.T(), result.RedirectURI, "https://client.app/callback")
		assert.Contains(s.T(), result.RedirectURI, "code="+result.Code)
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
		ctx := middleware.WithClientMetadata(context.Background(), "192.168.1.1", "Mozilla/5.0")

		s.mockUserStore.EXPECT().FindOrCreateByEmail(gomock.Any(), req.Email, gomock.Any()).Return(nil, assert.AnError)

		result, err := s.service.Authorize(ctx, &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
	})

	s.T().Run("session store error", func(t *testing.T) {
		req := baseReq
		ctx := middleware.WithClientMetadata(context.Background(), "192.168.1.1", "Mozilla/5.0")

		s.mockUserStore.EXPECT().FindOrCreateByEmail(gomock.Any(), req.Email, gomock.Any()).Return(existingUser, nil)
		s.mockCodeStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
		s.mockSessionStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return(assert.AnError)

		result, err := s.service.Authorize(ctx, &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
	})
}

// TestToken tests the OAuth 2.0 token exchange endpoint (PRD-001 FR-2)
func (s *ServiceSuite) TestToken_Exchange() {
	sessionID := uuid.New()
	userID := uuid.New()
	clientID := "client-123"
	redirectURI := "https://client.app/callback"
	code := "authz_12345"

	baseReq := models.TokenRequest{
		GrantType:   "authorization_code",
		Code:        code,
		RedirectURI: redirectURI,
		ClientID:    clientID,
	}

	validCodeRecord := &models.AuthorizationCodeRecord{
		Code:        code,
		SessionID:   sessionID,
		RedirectURI: redirectURI,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		Used:        false,
		CreatedAt:   time.Now().Add(-1 * time.Minute),
	}

	validSession := &models.Session{
		ID:             sessionID,
		UserID:         userID,
		ClientID:       clientID,
		RequestedScope: []string{"openid", "profile"},
		DeviceID:       "device-123",
		Status:         StatusPendingConsent, // Should be pending_consent before token exchange
		CreatedAt:      time.Now().Add(-5 * time.Minute),
		ExpiresAt:      time.Now().Add(24 * time.Hour),
	}

	s.T().Run("happy path - successful token exchange", func(t *testing.T) {
		req := baseReq
		codeRec := *validCodeRecord
		sess := *validSession
		ctx := middleware.WithDeviceID(middleware.WithClientMetadata(context.Background(), "192.168.1.1", "Mozilla/5.0"), sess.DeviceID)

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockCodeStore.EXPECT().MarkUsed(gomock.Any(), req.Code).Return(nil)
		s.mockJWT.EXPECT().GenerateAccessToken(userID, sessionID, clientID).Return("mock-access-token", nil)
		s.mockJWT.EXPECT().GenerateIDToken(userID, sessionID, clientID).Return("mock-id-token", nil)
		s.mockJWT.EXPECT().CreateRefreshToken().Return("ref_mock-refresh-token", nil)
		s.mockRefreshStore.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, token *models.RefreshTokenRecord) error {
				assert.Equal(s.T(), "ref_mock-refresh-token", token.Token)
				assert.Equal(s.T(), sessionID, token.SessionID)
				assert.False(s.T(), token.Used)
				assert.True(s.T(), token.ExpiresAt.After(time.Now()))
				return nil
			})
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		result, err := s.service.Token(ctx, &req)
		require.NoError(s.T(), err)
		assert.Equal(s.T(), "mock-access-token", result.AccessToken)
		assert.Equal(s.T(), "mock-id-token", result.IDToken)
		assert.Equal(s.T(), "ref_mock-refresh-token", result.RefreshToken)
		assert.Equal(s.T(), "Bearer", result.TokenType)
		assert.Equal(s.T(), s.service.tokenTTL, result.ExpiresIn)

		// Verify session status was updated to active
		assert.Equal(s.T(), StatusActive, sess.Status)
	})

	s.T().Run("session already active - idempotency", func(t *testing.T) {
		req := baseReq
		codeRec := *validCodeRecord
		sess := *validSession
		sess.Status = StatusActive // Already active
		ctx := middleware.WithDeviceID(middleware.WithClientMetadata(context.Background(), "192.168.1.1", "Mozilla/5.0"), sess.DeviceID)

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockCodeStore.EXPECT().MarkUsed(gomock.Any(), req.Code).Return(nil)
		s.mockJWT.EXPECT().GenerateAccessToken(userID, sessionID, clientID).Return("mock-access-token", nil)
		s.mockJWT.EXPECT().GenerateIDToken(userID, sessionID, clientID).Return("mock-id-token", nil)
		s.mockJWT.EXPECT().CreateRefreshToken().Return("ref_mock-refresh-token", nil)
		s.mockRefreshStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
		s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil)

		result, err := s.service.Token(ctx, &req)
		require.NoError(s.T(), err)
		assert.NotNil(s.T(), result)
		assert.Equal(s.T(), StatusActive, sess.Status) // Should remain active
	})

	// Table test for simple validation errors
	s.T().Run("validation errors", func(t *testing.T) {
		tests := []struct {
			name          string
			modifyReq     func(*models.TokenRequest)
			expectedCode  dErrors.Code
			expectLogAuth bool // Should this increment auth failure metrics?
		}{
			{
				name: "unsupported grant_type",
				modifyReq: func(r *models.TokenRequest) {
					r.GrantType = "password"
				},
				expectedCode:  dErrors.CodeBadRequest,
				expectLogAuth: false, // Client error, not security failure
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := baseReq
				tt.modifyReq(&req)

				result, err := s.service.Token(context.Background(), &req)
				assert.Error(t, err)
				assert.Nil(t, result)
				assert.True(t, dErrors.Is(err, tt.expectedCode))
			})
		}
	})

	// Authorization code validation errors (OAuth 2.0 Section 4.1.3)
	s.T().Run("authorization code not found", func(t *testing.T) {
		req := baseReq
		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(nil, sessionStore.ErrNotFound)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeUnauthorized))
		assert.Contains(s.T(), err.Error(), "invalid authorization code")
	})

	s.T().Run("authorization code expired", func(t *testing.T) {
		req := baseReq
		codeRec := *validCodeRecord
		codeRec.ExpiresAt = time.Now().Add(-5 * time.Minute) // Expired

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeUnauthorized))
		assert.Contains(s.T(), err.Error(), "expired")
	})

	s.T().Run("authorization code already used - replay attack", func(t *testing.T) {
		req := baseReq
		codeRec := *validCodeRecord
		codeRec.Used = true

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().RevokeSession(gomock.Any(), sessionID).Return(nil)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeUnauthorized))
		assert.Contains(s.T(), err.Error(), "already used")
	})

	s.T().Run("redirect_uri mismatch", func(t *testing.T) {
		req := baseReq
		req.RedirectURI = "https://evil.com/callback" // Different from code's redirect_uri
		codeRec := *validCodeRecord

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeBadRequest))
		assert.Contains(s.T(), err.Error(), "redirect_uri mismatch")
	})

	// Session validation errors
	s.T().Run("session not found", func(t *testing.T) {
		req := baseReq
		codeRec := *validCodeRecord

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(nil, sessionStore.ErrNotFound)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeUnauthorized))
	})

	s.T().Run("client_id mismatch", func(t *testing.T) {
		req := baseReq
		req.ClientID = "evil-client" // Different from session's client_id
		codeRec := *validCodeRecord
		sess := *validSession

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeBadRequest))
		assert.Contains(s.T(), err.Error(), "client_id mismatch")
	})

	s.T().Run("session revoked", func(t *testing.T) {
		req := baseReq
		codeRec := *validCodeRecord
		sess := *validSession
		sess.Status = "revoked"

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeUnauthorized))
		assert.Contains(s.T(), err.Error(), "revoked")
	})

	s.T().Run("session invalid status", func(t *testing.T) {
		req := baseReq
		codeRec := *validCodeRecord
		sess := *validSession
		sess.Status = "unknown_status"

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeUnauthorized))
		assert.Contains(s.T(), err.Error(), "invalid state")
	})

	s.T().Run("session expired", func(t *testing.T) {
		req := baseReq
		codeRec := *validCodeRecord
		sess := *validSession
		sess.ExpiresAt = time.Now().Add(-1 * time.Hour) // Expired

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeUnauthorized))
		assert.Contains(s.T(), err.Error(), "expired")
	})

	// Infrastructure errors
	s.T().Run("code store lookup error", func(t *testing.T) {
		req := baseReq
		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(nil, errors.New("db error"))

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeInternal))
	})

	s.T().Run("session store lookup error", func(t *testing.T) {
		req := baseReq
		codeRec := *validCodeRecord

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(nil, errors.New("db error"))

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeInternal))
	})

	s.T().Run("mark code used error", func(t *testing.T) {
		req := baseReq
		codeRec := *validCodeRecord
		sess := *validSession

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockCodeStore.EXPECT().MarkUsed(gomock.Any(), req.Code).Return(errors.New("write error"))

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeInternal))
	})

	s.T().Run("JWT generation errors", func(t *testing.T) {
		tests := []struct {
			name        string
			setupMocks  func()
			expectedErr string
		}{
			{
				name: "access token generation fails",
				setupMocks: func() {
					s.mockJWT.EXPECT().GenerateAccessToken(gomock.Any(), gomock.Any(), gomock.Any()).
						Return("", errors.New("jwt error"))
				},
				expectedErr: "failed to generate access token",
			},
			{
				name: "id token generation fails",
				setupMocks: func() {
					s.mockJWT.EXPECT().GenerateAccessToken(gomock.Any(), gomock.Any(), gomock.Any()).
						Return("mock-access", nil)
					s.mockJWT.EXPECT().GenerateIDToken(gomock.Any(), gomock.Any(), gomock.Any()).
						Return("", errors.New("jwt error"))
				},
				expectedErr: "failed to generate ID token",
			},
			{
				name: "refresh token generation fails",
				setupMocks: func() {
					s.mockJWT.EXPECT().GenerateAccessToken(gomock.Any(), gomock.Any(), gomock.Any()).
						Return("mock-access", nil)
					s.mockJWT.EXPECT().GenerateIDToken(gomock.Any(), gomock.Any(), gomock.Any()).
						Return("mock-id", nil)
					s.mockJWT.EXPECT().CreateRefreshToken().
						Return("", errors.New("jwt error"))
				},
				expectedErr: "failed to create refresh token",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := baseReq
				codeRec := *validCodeRecord
				sess := *validSession

				s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
				s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
				s.mockCodeStore.EXPECT().MarkUsed(gomock.Any(), req.Code).Return(nil)
				tt.setupMocks()

				result, err := s.service.Token(context.Background(), &req)
				assert.Error(t, err)
				assert.Nil(t, result)
				assert.True(t, dErrors.Is(err, dErrors.CodeInternal))
				assert.Contains(t, err.Error(), tt.expectedErr)
			})
		}
	})

	s.T().Run("refresh token store error", func(t *testing.T) {
		req := baseReq
		codeRec := *validCodeRecord
		sess := *validSession

		s.mockCodeStore.EXPECT().FindByCode(gomock.Any(), req.Code).Return(&codeRec, nil)
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), sessionID).Return(&sess, nil)
		s.mockCodeStore.EXPECT().MarkUsed(gomock.Any(), req.Code).Return(nil)
		s.mockJWT.EXPECT().GenerateAccessToken(userID, sessionID, clientID).Return("mock-access", nil)
		s.mockJWT.EXPECT().GenerateIDToken(userID, sessionID, clientID).Return("mock-id", nil)
		s.mockJWT.EXPECT().CreateRefreshToken().Return("ref_mock", nil)
		s.mockRefreshStore.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errors.New("store error"))

		result, err := s.service.Token(context.Background(), &req)
		assert.Error(s.T(), err)
		assert.Nil(s.T(), result)
		assert.True(s.T(), dErrors.Is(err, dErrors.CodeInternal))
	})
}

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
			Status: StatusActive,
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
			Status: StatusActive,
		}, nil)
		s.mockUserStore.EXPECT().FindByID(gomock.Any(), existingUser.ID).Return(nil, userStore.ErrNotFound)

		result, err := s.service.UserInfo(context.Background(), uuid.New().String())
		assert.ErrorIs(s.T(), err, dErrors.New(dErrors.CodeUnauthorized, "user not found"))
		assert.Nil(s.T(), result)
	})

	s.T().Run("session not active", func(t *testing.T) {
		s.mockSessionStore.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(&models.Session{
			Status: StatusPendingConsent,
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
			Status: StatusActive,
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

// TestDeleteUser tests the admin user deletion endpoint (PRD-001B)
func (s *ServiceSuite) TestDeleteUser() {
	ctx := context.Background()
	userID := uuid.New()
	existingUser := &models.User{ID: userID, Email: "user@example.com"}

	s.T().Run("deletes sessions then user", func(t *testing.T) {
		gomock.InOrder(
			s.mockUserStore.EXPECT().FindByID(ctx, userID).Return(existingUser, nil),
			s.mockSessionStore.EXPECT().DeleteSessionsByUser(ctx, userID).Return(nil),
			s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil),
			s.mockUserStore.EXPECT().Delete(ctx, userID).Return(nil),
			s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil),
		)

		err := s.service.DeleteUser(ctx, userID)
		assert.NoError(t, err)
	})

	s.T().Run("no sessions found still deletes user", func(t *testing.T) {
		gomock.InOrder(
			s.mockUserStore.EXPECT().FindByID(ctx, userID).Return(existingUser, nil),
			s.mockSessionStore.EXPECT().DeleteSessionsByUser(ctx, userID).Return(sessionStore.ErrNotFound),
			s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil), // sessions_revoked event
			s.mockUserStore.EXPECT().Delete(ctx, userID).Return(nil),
			s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil), // user_deleted event
		)

		err := s.service.DeleteUser(ctx, userID)
		assert.NoError(t, err)
	})

	s.T().Run("user lookup fails", func(t *testing.T) {
		s.mockUserStore.EXPECT().FindByID(ctx, userID).Return(nil, errors.New("db down"))

		err := s.service.DeleteUser(ctx, userID)
		require.Error(t, err)
		assert.True(t, dErrors.Is(err, dErrors.CodeInternal))
	})

	s.T().Run("user not found", func(t *testing.T) {
		s.mockUserStore.EXPECT().FindByID(ctx, userID).Return(nil, userStore.ErrNotFound)

		err := s.service.DeleteUser(ctx, userID)
		require.Error(t, err)
		assert.True(t, dErrors.Is(err, dErrors.CodeNotFound))
	})

	s.T().Run("session delete fails", func(t *testing.T) {
		gomock.InOrder(
			s.mockUserStore.EXPECT().FindByID(ctx, userID).Return(existingUser, nil),
			s.mockSessionStore.EXPECT().DeleteSessionsByUser(ctx, userID).Return(errors.New("redis down")),
		)

		err := s.service.DeleteUser(ctx, userID)
		require.Error(t, err)
		assert.True(t, dErrors.Is(err, dErrors.CodeInternal))
	})

	s.T().Run("user delete fails", func(t *testing.T) {
		gomock.InOrder(
			s.mockUserStore.EXPECT().FindByID(ctx, userID).Return(existingUser, nil),
			s.mockSessionStore.EXPECT().DeleteSessionsByUser(ctx, userID).Return(nil),
			s.mockAuditPublisher.EXPECT().Emit(gomock.Any(), gomock.Any()).Return(nil),
			s.mockUserStore.EXPECT().Delete(ctx, userID).Return(errors.New("write fail")),
		)

		err := s.service.DeleteUser(ctx, userID)
		require.Error(t, err)
		assert.True(t, dErrors.Is(err, dErrors.CodeInternal))
	})
}

func (s *ServiceSuite) TestToken_Refresh() {
		s.T().Run("refresh_token happy path (TODO PRD-016 FR-2)", func(t *testing.T) {
// 			1. Validate `grant_type` is `"refresh_token"`
// 2. Validate `refresh_token` and `client_id` are provided
// 3. Find session by refresh token in SessionStore
// 4. If session not found → 401 Invalid refresh token
// 5. Validate refresh token has not expired (< 30 days old)
// 6. Validate refresh token has not been revoked (session status != "revoked")
// 7. Validate device binding (see [DEVICE_BINDING.md](../DEVICE_BINDING.md) for validation logic)
// 8. **Refresh Token Rotation:**
//    - Revoke old refresh token (mark as used)
//    - Generate new refresh token
//    - Update session with new refresh token
// 9. Generate new access token (new expiry, same session_id)
// 10. Generate new ID token
// 11. Update session `LastRefreshedAt` timestamp
// 12. Emit audit event: `token_refreshed`
// 13. Return new tokens
		t.Skip("TODO(PRD-016): implement refresh_token grant flow (steps 1-13); requires extending TokenRequest with refresh_token and adding service logic + tests.")
	})

func (s *ServiceSuite) TestNewService_RequiresDepsAndConfig() {
	s.T().Run("missing stores fails", func(t *testing.T) {
		_, err := New(nil, nil, nil, nil, Config{})
		require.Error(t, err)
	})

	s.T().Run("sets defaults and applies jwt", func(t *testing.T) {

		svc, err := New(
			s.mockUserStore,
			s.mockSessionStore,
			s.mockCodeStore,
			s.mockRefreshStore,
			Config{}, // empty config
			WithJWTService(s.mockJWT),
		)
		require.NoError(t, err)
		assert.Equal(t, defaultSessionTTL, svc.sessionTTL)
		assert.Equal(t, defaultTokenTTL, svc.tokenTTL)
		assert.Equal(t, []string{"https"}, svc.allowedRedirectSchemes)
		assert.Equal(t, s.mockJWT, svc.jwt)
	})
}

func TestServiceSuite(t *testing.T) {
	suite.Run(t, new(ServiceSuite))
}
