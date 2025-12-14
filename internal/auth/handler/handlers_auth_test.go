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
	"credo/internal/auth/models"
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
	s.T().Run("forwards authorize request to service when scopes omitted", func(t *testing.T) {
		mockService, router := s.newHandler(t, nil)
		requestBody := `{"email":"user@example.com","client_id":"test-client-id","redirect_uri":"https://example.com/redirect"}`
		expectedReq := &authModel.AuthorizationRequest{
			Email:       "user@example.com",
			ClientID:    "test-client-id",
			RedirectURI: "https://example.com/redirect",
			State:       "",
		}
		expectedResp := &authModel.AuthorizationResult{
			Code:        "authz_code_123",
			RedirectURI: expectedReq.RedirectURI,
		}
		mockService.EXPECT().Authorize(gomock.Any(), expectedReq).Return(expectedResp, nil)

		status, got, errBody := s.doAuthRequest(t, router, requestBody)

		s.assertSuccessResponse(t, status, got, errBody)
		assert.Equal(t, expectedResp.Code, got.Code)
		assert.Equal(t, expectedResp.RedirectURI, got.RedirectURI)
	})

	s.T().Run("user is found and authorized - 200", func(t *testing.T) {
		mockService, router := s.newHandler(t, nil)
		expectedResp := &authModel.AuthorizationResult{
			Code:        "authz_code_123",
			RedirectURI: validRequest.RedirectURI,
		}
		mockService.EXPECT().Authorize(gomock.Any(), validRequest).Return(expectedResp, nil)

		status, got, errBody := s.doAuthRequest(t, router, s.mustMarshal(validRequest, t))

		s.assertSuccessResponse(t, status, got, errBody)
		assert.Equal(t, expectedResp.Code, got.Code)
		assert.Equal(t, expectedResp.RedirectURI, got.RedirectURI)
	})

	s.T().Run("400 - invalid json body", func(t *testing.T) {
		mockService, router := s.newHandler(t, nil)
		mockService.EXPECT().Authorize(gomock.Any(), gomock.Any()).Times(0)

		invalidJSON := `{"email": "`
		status, got, errBody := s.doAuthRequest(t, router, invalidJSON)

		s.assertErrorResponse(t, status, got, errBody, http.StatusBadRequest, string(dErrors.CodeBadRequest))
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
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				mockService, router := s.newHandler(t, nil)
				mockService.EXPECT().Authorize(gomock.Any(), tt.request).Return(nil, dErrors.New(dErrors.CodeBadRequest, "invalid request"))

				var body string
				if tt.body != "" {
					body = tt.body
				} else {
					body = s.mustMarshal(tt.request, t)
				}

				status, got, errBody := s.doAuthRequest(t, router, body)

				s.assertErrorResponse(t, status, got, errBody, http.StatusBadRequest, string(dErrors.CodeBadRequest))
			})
		}
	})

	s.T().Run("returns 500 when service fails", func(t *testing.T) {
		mockService, router := s.newHandler(t, nil)
		mockService.EXPECT().Authorize(gomock.Any(), validRequest).Return(nil, errors.New("boom"))

		status, got, errBody := s.doAuthRequest(t, router, s.mustMarshal(validRequest, t))

		s.assertErrorResponse(t, status, got, errBody, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})
}

func (s *AuthHandlerSuite) TestHandler_Token() {
	validRequest := &authModel.TokenRequest{
		GrantType:   string(models.GrantAuthorizationCode),
		Code:        "authz_code_123",
		RedirectURI: "https://example.com/callback",
		ClientID:    "some-client-id",
	}
	s.T().Run("happy path - tokens exchanged", func(t *testing.T) {
		mockService, router := s.newHandler(t, nil)
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

		s.assertSuccessResponse(t, status, got, errBody)
		assert.Equal(t, expectedResp.AccessToken, got.AccessToken)
		assert.Equal(t, expectedResp.IDToken, got.IDToken)
		assert.Equal(t, expectedResp.ExpiresIn, got.ExpiresIn)
	})

	s.T().Run("token response includes token_type", func(t *testing.T) {
		mockService, router := s.newHandler(t, nil)
		expectedResp := &authModel.TokenResult{
			AccessToken: "access-token-123",
			IDToken:     "id-token-123",
			ExpiresIn:   3600,
			TokenType:   "Bearer",
		}
		mockService.EXPECT().Token(gomock.Any(), gomock.Any()).Return(expectedResp, nil)

		status, _, errBody, raw := s.doTokenRequestRaw(t, router, s.mustMarshal(validRequest, t))

		s.assertSuccessResponse(t, status, raw, errBody)
		require.Contains(t, raw, "token_type")
		assert.Equal(t, "Bearer", raw["token_type"])
	})

	//- 400 Bad Request: Missing required fields (grant_type, code, redirect_uri, client_id)
	s.T().Run("missing required fields - 400", func(t *testing.T) {
		mockService, router := s.newHandler(t, nil)
		mockService.EXPECT().Token(gomock.Any(), gomock.Any()).Return(nil, dErrors.New(dErrors.CodeBadRequest, "missing fields"))
		missing := *validRequest
		missing.ClientID = ""

		status, got, errBody := s.doTokenRequest(t, router, s.mustMarshal(&missing, t))

		s.assertErrorResponse(t, status, got, errBody, http.StatusBadRequest, string(dErrors.CodeBadRequest))
	})

	// - 400 Bad Request: Unsupported grant_type (must be "authorization_code")
	s.T().Run("unsupported grant_type - 400", func(t *testing.T) {
		mockService, router := s.newHandler(t, nil)
		invalid := *validRequest
		invalid.GrantType = "invalid_grant"
		mockService.EXPECT().Token(gomock.Any(), &invalid).Return(nil, dErrors.New(dErrors.CodeBadRequest, "unsupported grant_type"))

		status, got, errBody := s.doTokenRequest(t, router, s.mustMarshal(&invalid, t))

		s.assertErrorResponse(t, status, got, errBody, http.StatusBadRequest, string(dErrors.CodeBadRequest))
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
				mockService, router := s.newHandler(t, nil)
				mockService.EXPECT().Token(gomock.Any(), gomock.Any()).Return(nil, tt.serviceErr)

				status, got, errBody := s.doTokenRequest(t, router, s.mustMarshal(validRequest, t))

				s.assertErrorResponse(t, status, got, errBody, http.StatusUnauthorized, string(dErrors.CodeUnauthorized))
			})
		}
	})

	// - 400 Bad Request: redirect_uri mismatch (doesn't match authorize request)
	s.T().Run("redirect_uri mismatch - 400", func(t *testing.T) {
		mockService, router := s.newHandler(t, nil)
		serviceErr := dErrors.New(dErrors.CodeBadRequest, "redirect_uri mismatch")
		mockService.EXPECT().Token(gomock.Any(), gomock.Any()).Return(nil, serviceErr)

		status, got, errBody := s.doTokenRequest(t, router, s.mustMarshal(validRequest, t))

		s.assertErrorResponse(t, status, got, errBody, http.StatusBadRequest, string(dErrors.CodeBadRequest))
	})

	// - 400 Bad Request: client_id mismatch (doesn't match authorize request)
	s.T().Run("client_id mismatch - 400", func(t *testing.T) {
		mockService, router := s.newHandler(t, nil)
		serviceErr := dErrors.New(dErrors.CodeBadRequest, "client_id mismatch")
		mockService.EXPECT().Token(gomock.Any(), gomock.Any()).Return(nil, serviceErr)

		status, got, errBody := s.doTokenRequest(t, router, s.mustMarshal(validRequest, t))

		s.assertErrorResponse(t, status, got, errBody, http.StatusBadRequest, string(dErrors.CodeBadRequest))
	})
	// - 500 Internal Server Error: Store failure
	s.T().Run("internal server failure - 500", func(t *testing.T) {
		mockService, router := s.newHandler(t, nil)
		mockService.EXPECT().Token(gomock.Any(), gomock.Any()).Return(nil, errors.New("database error"))
		status, got, errBody := s.doTokenRequest(t, router, s.mustMarshal(validRequest, t))

		s.assertErrorResponse(t, status, got, errBody, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})
}

func (s *AuthHandlerSuite) TestHandler_UserInfo() {
	validSessionID := uuid.New()
	s.T().Run("happy path - user info returned", func(t *testing.T) {
		mockService, router := s.newHandler(t, nil)
		expectedResp := &authModel.UserInfoResult{
			Sub:           "user-123",
			Email:         "user@example.com",
			EmailVerified: true,
			GivenName:     "Ahmed",
			FamilyName:    "Mustafa",
			Name:          "Ahmed Mustafa",
		}
		mockService.EXPECT().UserInfo(gomock.Any(), validSessionID.String()).Return(expectedResp, nil)

		status, got, errBody := s.doUserInfoRequest(t, router, validSessionID.String())

		s.assertSuccessResponse(t, status, got, errBody)
		assert.Equal(t, expectedResp.Sub, got.Sub)
		assert.Equal(t, expectedResp.Email, got.Email)
		assert.Equal(t, expectedResp.EmailVerified, got.EmailVerified)
		assert.Equal(t, expectedResp.GivenName, got.GivenName)
		assert.Equal(t, expectedResp.FamilyName, got.FamilyName)
		assert.Equal(t, expectedResp.Name, got.Name)
	})

	// 	- 401 Unauthorized: Missing or invalid Authorization header
	s.T().Run("missing or invalid authorization header - 401", func(t *testing.T) {
		mockService, router := s.newHandler(t, nil)
		mockService.EXPECT().UserInfo(gomock.Any(), "").Return(nil, dErrors.New(dErrors.CodeUnauthorized, "missing or invalid session"))

		status, got, errBody := s.doUserInfoRequest(t, router, "")

		s.assertErrorResponse(t, status, got, errBody, http.StatusUnauthorized, string(dErrors.CodeUnauthorized))
	})

	s.T().Run("invalid session identifier format - 401", func(t *testing.T) {
		mockService, router := s.newHandler(t, nil)
		invalidSession := "not-a-uuid"
		mockService.EXPECT().UserInfo(gomock.Any(), invalidSession).Return(nil, dErrors.New(dErrors.CodeUnauthorized, "invalid session ID"))

		status, got, errBody := s.doUserInfoRequest(t, router, invalidSession)

		s.assertErrorResponse(t, status, got, errBody, http.StatusUnauthorized, string(dErrors.CodeUnauthorized))
	})

	// - 401 Unauthorized: session not found or expired
	s.T().Run("session not found or expired - 401", func(t *testing.T) {
		mockService, router := s.newHandler(t, nil)
		serviceErr := dErrors.New(dErrors.CodeUnauthorized, "session not found or expired")
		mockService.EXPECT().UserInfo(gomock.Any(), validSessionID.String()).Return(nil, serviceErr)

		status, got, errBody := s.doUserInfoRequest(t, router, validSessionID.String())

		s.assertErrorResponse(t, status, got, errBody, http.StatusUnauthorized, string(dErrors.CodeUnauthorized))
	})

	// - 401 Unauthorized: User not found
	s.T().Run("user not found - 401", func(t *testing.T) {
		mockService, router := s.newHandler(t, nil)
		serviceErr := dErrors.New(dErrors.CodeUnauthorized, "user not found")
		mockService.EXPECT().UserInfo(gomock.Any(), validSessionID.String()).Return(nil, serviceErr)

		status, got, errBody := s.doUserInfoRequest(t, router, validSessionID.String())

		s.assertErrorResponse(t, status, got, errBody, http.StatusUnauthorized, string(dErrors.CodeUnauthorized))
	})

	s.T().Run("internal server failure - 500", func(t *testing.T) {
		mockService, router := s.newHandler(t, nil)
		mockService.EXPECT().UserInfo(gomock.Any(), validSessionID.String()).Return(nil, errors.New("database error"))

		status, got, errBody := s.doUserInfoRequest(t, router, validSessionID.String())

		s.assertErrorResponse(t, status, got, errBody, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})
}

func (s *AuthHandlerSuite) TestHandler_ListSessions() {
	userID := uuid.New()
	currentSessionID := uuid.New()

	s.T().Run("happy path - lists sessions", func(t *testing.T) {
		mockService, router := s.newHandler(t, nil)
		expected := &authModel.SessionsResult{
			Sessions: []authModel.SessionSummary{
				{
					SessionID: currentSessionID.String(),
					Device:    "Chrome on macOS",
					IsCurrent: true,
				},
			},
		}

		mockService.EXPECT().
			ListSessions(gomock.Any(), userID, currentSessionID).
			Return(expected, nil)

		status, got, errBody := s.doListSessionsRequest(t, router, userID.String(), currentSessionID.String())
		s.assertSuccessResponse(t, status, got, errBody)
		require.NotNil(t, got)
		require.Len(t, got.Sessions, 1)
		assert.Equal(t, currentSessionID.String(), got.Sessions[0].SessionID)
		assert.True(t, got.Sessions[0].IsCurrent)
	})

	s.T().Run("invalid user id in context - 401", func(t *testing.T) {
		mockService, router := s.newHandler(t, nil)
		mockService.EXPECT().ListSessions(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		status, got, errBody := s.doListSessionsRequest(t, router, "not-a-uuid", currentSessionID.String())
		s.assertErrorResponse(t, status, got, errBody, http.StatusUnauthorized, string(dErrors.CodeUnauthorized))
	})

	s.T().Run("invalid session id in context - 401", func(t *testing.T) {
		mockService, router := s.newHandler(t, nil)
		mockService.EXPECT().ListSessions(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		status, got, errBody := s.doListSessionsRequest(t, router, userID.String(), "not-a-uuid")
		s.assertErrorResponse(t, status, got, errBody, http.StatusUnauthorized, string(dErrors.CodeUnauthorized))
	})

	s.T().Run("service error - 500", func(t *testing.T) {
		mockService, router := s.newHandler(t, nil)
		mockService.EXPECT().
			ListSessions(gomock.Any(), userID, currentSessionID).
			Return(nil, errors.New("boom"))

		status, got, errBody := s.doListSessionsRequest(t, router, userID.String(), currentSessionID.String())
		s.assertErrorResponse(t, status, got, errBody, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})
}

func (s *AuthHandlerSuite) TestHandler_RevokeSession() {
	userID := uuid.New()
	sessionID := uuid.New()
	path := "/auth/sessions/" + sessionID.String()

	s.T().Run("happy path - revokes session", func(t *testing.T) {
		mockService, router := s.newHandler(t, nil)
		mockService.EXPECT().RevokeSession(gomock.Any(), userID, sessionID).Return(nil)

		status, got, errBody := s.doRevokeSessionRequest(t, router, path, userID.String())
		s.assertSuccessResponse(t, status, got, errBody)
		assert.True(t, got.Revoked)
		assert.Equal(t, sessionID.String(), got.SessionID)
	})

	s.T().Run("invalid user id in context - 401", func(t *testing.T) {
		mockService, router := s.newHandler(t, nil)
		mockService.EXPECT().RevokeSession(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		status, got, errBody := s.doRevokeSessionRequest(t, router, path, "not-a-uuid")
		s.assertErrorResponse(t, status, got, errBody, http.StatusUnauthorized, string(dErrors.CodeUnauthorized))
	})

	s.T().Run("invalid session id in path - 400", func(t *testing.T) {
		mockService, router := s.newHandler(t, nil)
		mockService.EXPECT().RevokeSession(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		status, got, errBody := s.doRevokeSessionRequest(t, router, "/auth/sessions/not-a-uuid", userID.String())
		s.assertErrorResponse(t, status, got, errBody, http.StatusBadRequest, string(dErrors.CodeBadRequest))
	})
}

func (s *AuthHandlerSuite) TestHandler_AdminDeleteUser() {
	userID := uuid.New()
	validPath := "/admin/auth/users/" + userID.String()

	s.T().Run("deletes user", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockService := mocks.NewMockService(ctrl)
		logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
		handler := New(mockService, logger, "__Secure-Device-ID", 31536000)

		r := chi.NewRouter()
		handler.RegisterAdmin(r)

		mockService.EXPECT().DeleteUser(gomock.Any(), userID).Return(nil)

		req := httptest.NewRequest(http.MethodDelete, validPath, nil)
		req.Header.Set("X-Admin-Token", "demo-admin-token")
		recorder := httptest.NewRecorder()

		r.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusNoContent, recorder.Code)
	})

	s.T().Run("invalid user id", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockService := mocks.NewMockService(ctrl)
		logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
		handler := New(mockService, logger, "__Secure-Device-ID", 31536000)

		r := chi.NewRouter()
		handler.RegisterAdmin(r)

		req := httptest.NewRequest(http.MethodDelete, "/admin/auth/users/not-a-uuid", nil)
		recorder := httptest.NewRecorder()

		r.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusBadRequest, recorder.Code)
	})

	s.T().Run("service error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockService := mocks.NewMockService(ctrl)
		logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
		handler := New(mockService, logger, "__Secure-Device-ID", 31536000)

		r := chi.NewRouter()
		handler.RegisterAdmin(r)

		mockService.EXPECT().DeleteUser(gomock.Any(), userID).Return(errors.New("boom"))

		req := httptest.NewRequest(http.MethodDelete, validPath, nil)
		recorder := httptest.NewRecorder()

		r.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	})
}

func TestAuthHandlerSuite(t *testing.T) {
	suite.Run(t, new(AuthHandlerSuite))
}

func (s *AuthHandlerSuite) newHandler(t *testing.T, allowedSchemes *[]string) (*mocks.MockService, *chi.Mux) {
	t.Helper()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	if allowedSchemes == nil {
		defaultSchemes := []string{"http", "https"}
		allowedSchemes = &defaultSchemes
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	mockService := mocks.NewMockService(ctrl)
	handler := New(mockService, logger, "__Secure-Device-ID", 31536000)
	r := chi.NewRouter()
	handler.Register(r)
	return mockService, r
}

func (s *AuthHandlerSuite) doUserInfoRequest(t *testing.T, router *chi.Mux, sessionID string) (int, *authModel.UserInfoResult, map[string]string) {
	t.Helper()
	httpReq := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)

	// Inject session ID into context (simulating what the auth middleware would do)
	if sessionID != "" {
		ctx := httpReq.Context()
		ctx = context.WithValue(ctx, middleware.ContextKeySessionID, sessionID)
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

func (s *AuthHandlerSuite) doListSessionsRequest(t *testing.T, router *chi.Mux, userID string, sessionID string) (int, *authModel.SessionsResult, map[string]string) {
	t.Helper()
	httpReq := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)

	ctx := httpReq.Context()
	if userID != "" {
		ctx = context.WithValue(ctx, middleware.ContextKeyUserID, userID)
	}
	if sessionID != "" {
		ctx = context.WithValue(ctx, middleware.ContextKeySessionID, sessionID)
	}
	httpReq = httpReq.WithContext(ctx)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httpReq)

	raw, err := io.ReadAll(rr.Body)
	require.NoError(t, err)

	if rr.Code == http.StatusOK {
		var res authModel.SessionsResult
		require.NoError(t, json.Unmarshal(raw, &res))
		return rr.Code, &res, nil
	}

	var errBody map[string]string
	require.NoError(t, json.Unmarshal(raw, &errBody))
	return rr.Code, nil, errBody
}

func (s *AuthHandlerSuite) doRevokeSessionRequest(t *testing.T, router *chi.Mux, path string, userID string) (int, *authModel.SessionRevocationResult, map[string]string) {
	t.Helper()
	httpReq := httptest.NewRequest(http.MethodDelete, path, nil)

	ctx := httpReq.Context()
	if userID != "" {
		ctx = context.WithValue(ctx, middleware.ContextKeyUserID, userID)
	}
	httpReq = httpReq.WithContext(ctx)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httpReq)

	raw, err := io.ReadAll(rr.Body)
	require.NoError(t, err)

	if rr.Code == http.StatusOK {
		var res authModel.SessionRevocationResult
		require.NoError(t, json.Unmarshal(raw, &res))
		return rr.Code, &res, nil
	}

	var errBody map[string]string
	require.NoError(t, json.Unmarshal(raw, &errBody))
	return rr.Code, nil, errBody
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

func (s *AuthHandlerSuite) doTokenRequestRaw(t *testing.T, router *chi.Mux, body string) (int, *authModel.TokenResult, map[string]string, map[string]any) {
	t.Helper()
	httpReq := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, httpReq)
	raw, err := io.ReadAll(rr.Body)
	require.NoError(t, err)

	if rr.Code == http.StatusOK {
		var res map[string]any
		require.NoError(t, json.Unmarshal(raw, &res))
		return rr.Code, nil, nil, res
	}

	var errBody map[string]string
	require.NoError(t, json.Unmarshal(raw, &errBody))
	return rr.Code, nil, errBody, nil
}

func (s *AuthHandlerSuite) mustMarshal(v any, t *testing.T) string {
	t.Helper()
	body, err := json.Marshal(v)
	require.NoError(t, err)
	return string(body)
}

func (s *AuthHandlerSuite) assertErrorResponse(t *testing.T, status int, got interface{}, errBody map[string]string, expectedStatus int, expectedCode string) {
	t.Helper()
	assert.Equal(t, expectedStatus, status)
	assert.Nil(t, got)
	assert.Equal(t, expectedCode, errBody["error"])
}

func (s *AuthHandlerSuite) assertSuccessResponse(t *testing.T, status int, got interface{}, errBody map[string]string) {
	t.Helper()
	assert.Equal(t, http.StatusOK, status)
	assert.NotNil(t, got)
	assert.Nil(t, errBody)
}
