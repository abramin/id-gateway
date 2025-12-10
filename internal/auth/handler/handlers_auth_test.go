package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	"credo/internal/auth/handler/mocks"
	authModel "credo/internal/auth/models"
	"credo/internal/platform/middleware"
	dErrors "credo/pkg/domain-errors"
)

//go:generate mockgen -source=handler.go -destination=mocks/auth-mocks.go -package=mocks Service
type AuthHandlerSuite struct {
	suite.Suite
	ctx context.Context
}

func (s *AuthHandlerSuite) SetupSuite() {
	s.ctx = context.Background()
}

func (s *AuthHandlerSuite) TestHandler_Authorize() {
	var validRequest = &authModel.AuthorizationRequest{
		Email:       "user@example.com",
		ClientID:    "test-client-id",
		Scopes:      []string{"scope1", "scope2"},
		RedirectURI: "https://example.com/redirect",
		State:       "test-state",
	}
	s.T().Run("user is found and authorized - 200", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		expectedResp := &authModel.AuthorizationResult{
			Code:        "authz_" + uuid.New().String(),
			RedirectURI: validRequest.RedirectURI,
		}
		mockService.EXPECT().Authorize(gomock.Any(), validRequest).Return(expectedResp, nil)

		status, got, errBody := s.doAuthRequest(t, router, s.mustMarshal(validRequest, t))

		assert.Equal(t, http.StatusOK, status)
		assert.NotNil(t, got)
		assert.Nil(t, errBody)
		assert.Equal(t, expectedResp.Code, got.Code)
		assert.Equal(t, expectedResp.RedirectURI, got.RedirectURI)
	})

	s.T().Run("400 - invalid json body", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().Authorize(gomock.Any(), gomock.Any()).Times(0)

		invalidJSON := `{"email": "`
		status, got, errBody := s.doAuthRequest(t, router, invalidJSON)

		assert.Equal(t, http.StatusBadRequest, status)
		assert.Nil(t, got)
		assert.Equal(t, string(dErrors.CodeBadRequest), errBody["error"])
	})

	s.T().Run("400 error scenarios - invalid input", func(t *testing.T) {
		tests := []struct {
			name    string
			request *authModel.AuthorizationRequest
			body    string
		}{
			{
				name: "invalid email",
				request: &authModel.AuthorizationRequest{
					Email:       "invalid-email",
					ClientID:    "test-client-id",
					Scopes:      []string{"scope1", "scope2"},
					RedirectURI: "https://example.com/redirect",
					State:       "test-state",
				},
			},
			{
				name: "invalid redirect URI",
				request: &authModel.AuthorizationRequest{
					Email:       "user@example.com",
					ClientID:    "test-client-id",
					Scopes:      []string{"scope1", "scope2"},
					RedirectURI: "invalid-uri",
					State:       "test-state",
				},
			},
			{
				name: "missing client ID",
				request: &authModel.AuthorizationRequest{
					Email:       "user@example.com",
					ClientID:    "",
					Scopes:      []string{"scope1", "scope2"},
					RedirectURI: "https://example.com/redirect",
					State:       "test-state",
				},
			},
			{
				name: "scopes contain empty value",
				request: &authModel.AuthorizationRequest{
					Email:       "user@example.com",
					ClientID:    "test-client-id",
					Scopes:      []string{"scope1", " "},
					RedirectURI: "https://example.com/redirect",
					State:       "test-state",
				},
			},
			{
				name: "scopes list is empty",
				request: &authModel.AuthorizationRequest{
					Email:       "user@example.com",
					ClientID:    "test-client-id",
					Scopes:      []string{},
					RedirectURI: "https://example.com/redirect",
					State:       "test-state",
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				mockService, router := s.newHandler(t)
				mockService.EXPECT().Authorize(gomock.Any(), gomock.Any()).Times(0)

				var body string
				if tt.body != "" {
					body = tt.body
				} else {
					body = s.mustMarshal(tt.request, t)
				}

				status, got, errBody := s.doAuthRequest(t, router, body)

				assert.Equal(t, http.StatusBadRequest, status)
				assert.Nil(t, got)
				assert.Equal(t, string(dErrors.CodeBadRequest), errBody["error"])
			})
		}
	})

	s.T().Run("returns 500 when service fails", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().Authorize(gomock.Any(), validRequest).Return(nil, errors.New("boom"))

		status, got, errBody := s.doAuthRequest(t, router, s.mustMarshal(validRequest, t))

		assert.Equal(t, http.StatusInternalServerError, status)
		assert.Nil(t, got)
		assert.Equal(t, "internal_error", errBody["error"])
	})
}

func (s *AuthHandlerSuite) TestHandler_Token() {
	validRequest := &authModel.TokenRequest{
		GrantType:   "authorization_code",
		Code:        "authz_code_123",
		RedirectURI: "https://example.com/callback",
		ClientID:    "some-client-id",
	}
	s.T().Run("happy path - tokens exchanged", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		expectedResp := &authModel.TokenResult{
			AccessToken: "access-token-123",
			IDToken:     "id-token-123",
			ExpiresIn:   3600,
		}
		mockService.EXPECT().Token(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, req *authModel.TokenRequest) (*authModel.TokenResult, error) {
				assert.Equal(t, validRequest.GrantType, req.GrantType)
				assert.Equal(t, validRequest.Code, req.Code)
				assert.Equal(t, validRequest.RedirectURI, req.RedirectURI)
				assert.Equal(t, validRequest.ClientID, req.ClientID)
				return expectedResp, nil
			})

		status, got, errBody := s.doTokenRequest(t, router, s.mustMarshal(validRequest, t))

		assert.Equal(t, http.StatusOK, status)
		assert.NotNil(t, got)
		assert.Nil(t, errBody)
		assert.Equal(t, expectedResp.AccessToken, got.AccessToken)
		assert.Equal(t, expectedResp.IDToken, got.IDToken)
		assert.Equal(t, expectedResp.ExpiresIn, got.ExpiresIn)
	})

	//- 400 Bad Request: Missing required fields (grant_type, code, redirect_uri, client_id)
	s.T().Run("missing required fields - 400", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().Token(gomock.Any(), gomock.Any()).Times(0)
		missing := *validRequest
		missing.ClientID = ""

		status, got, errBody := s.doTokenRequest(t, router, s.mustMarshal(&missing, t))

		assert.Equal(t, http.StatusBadRequest, status)
		assert.Nil(t, got)
		assert.Equal(t, string(dErrors.CodeBadRequest), errBody["error"])
	})

	// - 400 Bad Request: Unsupported grant_type (must be "authorization_code")
	s.T().Run("unsupported grant_type - 400", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		invalid := *validRequest
		invalid.GrantType = "invalid_grant"
		mockService.EXPECT().Token(gomock.Any(), gomock.Any()).Times(0)

		status, got, errBody := s.doTokenRequest(t, router, s.mustMarshal(&invalid, t))

		assert.Equal(t, http.StatusBadRequest, status)
		assert.Nil(t, got)
		assert.Equal(t, string(dErrors.CodeBadRequest), errBody["error"])
	})
	// - 401 Unauthorized: Invalid authorization code (not found)
	// - 401 Unauthorized: Authorization code expired (> 10 minutes old)
	// - 401 Unauthorized: Authorization code already used (replay attack prevention)
	s.T().Run("unauthorized scenarios - 401", func(t *testing.T) {
		tests := []struct {
			name       string
			serviceErr error
		}{
			{
				name:       "invalid authorization code",
				serviceErr: dErrors.New(dErrors.CodeUnauthorized, "invalid authorization code"),
			},
			{
				name:       "authorization code expired",
				serviceErr: dErrors.New(dErrors.CodeUnauthorized, "authorization code expired"),
			},
			{
				name:       "authorization code already used",
				serviceErr: dErrors.New(dErrors.CodeUnauthorized, "authorization code already used"),
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				mockService, router := s.newHandler(t)
				mockService.EXPECT().Token(gomock.Any(), gomock.Any()).Return(nil, tt.serviceErr)

				status, got, errBody := s.doTokenRequest(t, router, s.mustMarshal(validRequest, t))

				assert.Equal(t, http.StatusUnauthorized, status)
				assert.Nil(t, got)
				assert.Equal(t, string(dErrors.CodeUnauthorized), errBody["error"])
			})
		}
	})

	// - 400 Bad Request: redirect_uri mismatch (doesn't match authorize request)
	s.T().Run("redirect_uri mismatch - 400", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		serviceErr := dErrors.New(dErrors.CodeBadRequest, "redirect_uri mismatch")
		mockService.EXPECT().Token(gomock.Any(), gomock.Any()).Return(nil, serviceErr)

		status, got, errBody := s.doTokenRequest(t, router, s.mustMarshal(validRequest, t))

		assert.Equal(t, http.StatusBadRequest, status)
		assert.Nil(t, got)
		assert.Equal(t, string(dErrors.CodeBadRequest), errBody["error"])
	})

	// - 400 Bad Request: client_id mismatch (doesn't match authorize request)
	s.T().Run("client_id mismatch - 400", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		serviceErr := dErrors.New(dErrors.CodeBadRequest, "client_id mismatch")
		mockService.EXPECT().Token(gomock.Any(), gomock.Any()).Return(nil, serviceErr)

		status, got, errBody := s.doTokenRequest(t, router, s.mustMarshal(validRequest, t))
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Nil(t, got)
		assert.Equal(t, string(dErrors.CodeBadRequest), errBody["error"])
	})
	// - 500 Internal Server Error: Store failure
	s.T().Run("internal server failure - 500", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().Token(gomock.Any(), gomock.Any()).Return(nil, errors.New("database error"))
		status, got, errBody := s.doTokenRequest(t, router, s.mustMarshal(validRequest, t))

		assert.Equal(t, http.StatusInternalServerError, status)
		assert.Nil(t, got)
		assert.Equal(t, "internal_error", errBody["error"])
	})
}

func (s *AuthHandlerSuite) TestHandler_UserInfo() {
	validSessionID := uuid.New()
	s.T().Run("happy path - user info returned", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		expectedResp := &authModel.UserInfoResult{
			Sub:           "user-123",
			Email:         "user@example.com",
			EmailVerified: true,
			GivenName:     "Ahmed",
			FamilyName:    "Mustafa",
			Name:          "Ahmed Mustafa",
		}
		mockService.EXPECT().UserInfo(gomock.Any(), validSessionID).Return(expectedResp, nil)

		status, got, errBody := s.doUserInfoRequest(t, router, validSessionID)

		assert.Equal(t, http.StatusOK, status)
		assert.NotNil(t, got)
		assert.Nil(t, errBody)
		assert.Equal(t, expectedResp.Sub, got.Sub)
		assert.Equal(t, expectedResp.Email, got.Email)
		assert.Equal(t, expectedResp.EmailVerified, got.EmailVerified)
		assert.Equal(t, expectedResp.GivenName, got.GivenName)
		assert.Equal(t, expectedResp.FamilyName, got.FamilyName)
		assert.Equal(t, expectedResp.Name, got.Name)
	})

	// 	- 401 Unauthorized: Missing or invalid Authorization header
	s.T().Run("missing or invalid authorization header - 401", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().UserInfo(gomock.Any(), gomock.Any()).Times(0)

		status, got, errBody := s.doUserInfoRequest(t, router, uuid.Nil)
		assert.Equal(t, http.StatusUnauthorized, status)
		assert.Nil(t, got)
		assert.Equal(t, string(dErrors.CodeUnauthorized), errBody["error"])
	})

	// - 401 Unauthorized: session not found or expired
	s.T().Run("session not found or expired - 401", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		serviceErr := dErrors.New(dErrors.CodeUnauthorized, "session not found or expired")
		mockService.EXPECT().UserInfo(gomock.Any(), validSessionID).Return(nil, serviceErr)

		status, got, errBody := s.doUserInfoRequest(t, router, validSessionID)

		assert.Equal(t, http.StatusUnauthorized, status)
		assert.Nil(t, got)
		assert.Equal(t, string(dErrors.CodeUnauthorized), errBody["error"])
	})

	// - 401 Unauthorized: User not found
	s.T().Run("user not found - 401", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		serviceErr := dErrors.New(dErrors.CodeUnauthorized, "user not found")
		mockService.EXPECT().UserInfo(gomock.Any(), validSessionID).Return(nil, serviceErr)

		status, got, errBody := s.doUserInfoRequest(t, router, validSessionID)

		assert.Equal(t, http.StatusUnauthorized, status)
		assert.Nil(t, got)
		assert.Equal(t, string(dErrors.CodeUnauthorized), errBody["error"])
	})

	s.T().Run("internal server failure - 500", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().UserInfo(gomock.Any(), validSessionID).Return(nil, errors.New("database error"))

		status, got, errBody := s.doUserInfoRequest(t, router, validSessionID)

		assert.Equal(t, http.StatusInternalServerError, status)
		assert.Nil(t, got)
		assert.Equal(t, "internal_error", errBody["error"])
	})
}

func TestAuthHandlerSuite(t *testing.T) {
	suite.Run(t, new(AuthHandlerSuite))
}

func (s *AuthHandlerSuite) newHandler(t *testing.T) (*mocks.MockAuthService, *chi.Mux) {
	t.Helper()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	mockService := mocks.NewMockAuthService(ctrl)
	handler := New(mockService, logger, false, nil)
	r := chi.NewRouter()
	handler.Register(r)
	return mockService, r
}

func (s *AuthHandlerSuite) doUserInfoRequest(t *testing.T, router *chi.Mux, sessionID uuid.UUID) (int, *authModel.UserInfoResult, map[string]string) {
	t.Helper()
	httpReq := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)

	// Inject session ID into context (simulating what the auth middleware would do)
	if sessionID != uuid.Nil {
		ctx := httpReq.Context()
		ctx = context.WithValue(ctx, middleware.ContextKeySessionID, sessionID.String())
		httpReq = httpReq.WithContext(ctx)
	}

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httpReq)

	raw, err := io.ReadAll(rr.Body)
	require.NoError(t, err)

	if rr.Code == http.StatusOK {
		var res authModel.UserInfoResult
		require.NoError(t, json.Unmarshal(raw, &res))
		return rr.Code, &res, nil
	} else {
		var errBody map[string]string
		require.NoError(t, json.Unmarshal(raw, &errBody))
		return rr.Code, nil, errBody
	}
}

func (s *AuthHandlerSuite) doAuthRequest(t *testing.T, router *chi.Mux, body string) (int, *authModel.AuthorizationResult, map[string]string) {
	t.Helper()
	httpReq := httptest.NewRequest(http.MethodPost, "/auth/authorize", strings.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, httpReq)

	raw, err := io.ReadAll(rr.Body)
	require.NoError(t, err)

	if rr.Code == http.StatusOK {
		var res authModel.AuthorizationResult
		require.NoError(t, json.Unmarshal(raw, &res))
		return rr.Code, &res, nil
	} else {
		var errBody map[string]string
		require.NoError(t, json.Unmarshal(raw, &errBody))
		return rr.Code, nil, errBody
	}
}

func (s *AuthHandlerSuite) doTokenRequest(t *testing.T, router *chi.Mux, body string) (int, *authModel.TokenResult, map[string]string) {
	t.Helper()
	httpReq := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, httpReq)
	raw, err := io.ReadAll(rr.Body)
	require.NoError(t, err)

	if rr.Code == http.StatusOK {
		var res authModel.TokenResult
		require.NoError(t, json.Unmarshal(raw, &res))
		return rr.Code, &res, nil
	} else {
		var errBody map[string]string
		require.NoError(t, json.Unmarshal(raw, &errBody))
		return rr.Code, nil, errBody
	}
}

func (s *AuthHandlerSuite) mustMarshal(v any, t *testing.T) string {
	t.Helper()
	body, err := json.Marshal(v)
	require.NoError(t, err)
	return string(body)
}
