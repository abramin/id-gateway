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
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	authmw "credo/pkg/platform/middleware/auth"
)

//go:generate mockgen -source=handler.go -destination=mocks/auth-mocks.go -package=mocks Service

// AuthHandlerSuite tests handler-specific behavior.
// NOTE: Happy paths and input validation scenarios are covered by Cucumber E2E tests
// in e2e/features/auth_*.feature. These unit tests focus on handler-specific logic:
// - Context value extraction
// - Internal error mapping to 500 responses
type AuthHandlerSuite struct {
	suite.Suite
	ctx context.Context
}

func (s *AuthHandlerSuite) SetupSuite() {
	s.ctx = context.Background()
}

func (s *AuthHandlerSuite) TestHandler_Authorize() {
	var validRequest = &models.AuthorizationRequest{
		Email:       "user@example.com",
		ClientID:    "test-client-id",
		Scopes:      []string{"scope1", "scope2"},
		RedirectURI: "https://example.com/redirect",
		State:       "test-state",
	}

	s.T().Run("forwards authorize request to service with default scope when scopes omitted", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		requestBody := `{"email":"user@example.com","client_id":"test-client-id","redirect_uri":"https://example.com/redirect"}`
		// Handler normalizes the request, adding default "openid" scope when omitted
		expectedReq := &models.AuthorizationRequest{
			Email:       "user@example.com",
			ClientID:    "test-client-id",
			Scopes:      []string{"openid"},
			RedirectURI: "https://example.com/redirect",
			State:       "",
		}
		expectedResp := &models.AuthorizationResult{
			Code:        "authz_code_123",
			RedirectURI: expectedReq.RedirectURI,
		}
		mockService.EXPECT().Authorize(gomock.Any(), expectedReq).Return(expectedResp, nil)

		status, got, errBody := s.doAuthRequest(t, router, requestBody)

		s.assertSuccessResponse(t, status, got, errBody)
		assert.Equal(t, expectedResp.Code, got.Code)
		assert.Equal(t, expectedResp.RedirectURI, got.RedirectURI)
	})

	s.T().Run("returns 500 when service fails", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().Authorize(gomock.Any(), validRequest).Return(nil, errors.New("boom"))

		status, got, errBody := s.doAuthRequest(t, router, s.mustMarshal(validRequest, t))

		s.assertErrorResponse(t, status, got, errBody, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})
}

func (s *AuthHandlerSuite) TestHandler_Token() {
	validRequest := &models.TokenRequest{
		GrantType:   string(models.GrantAuthorizationCode),
		Code:        "authz_code_123",
		RedirectURI: "https://example.com/callback",
		ClientID:    "some-client-id",
	}

	s.T().Run("token response includes token_type", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		expectedResp := &models.TokenResult{
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

	s.T().Run("internal server failure - 500", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().Token(gomock.Any(), gomock.Any()).Return(nil, errors.New("database error"))
		status, got, errBody := s.doTokenRequest(t, router, s.mustMarshal(validRequest, t))

		s.assertErrorResponse(t, status, got, errBody, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})
}

func (s *AuthHandlerSuite) TestHandler_UserInfo() {
	validSessionID := uuid.New()

	s.T().Run("missing or invalid authorization header - 401", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().UserInfo(gomock.Any(), "").Return(nil, dErrors.New(dErrors.CodeUnauthorized, "missing or invalid session"))

		status, got, errBody := s.doUserInfoRequest(t, router, "")

		s.assertErrorResponse(t, status, got, errBody, http.StatusUnauthorized, string(dErrors.CodeUnauthorized))
	})

	s.T().Run("invalid session identifier format - 401", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		invalidSession := "not-a-uuid"
		mockService.EXPECT().UserInfo(gomock.Any(), invalidSession).Return(nil, dErrors.New(dErrors.CodeUnauthorized, "invalid session ID"))

		status, got, errBody := s.doUserInfoRequest(t, router, invalidSession)

		s.assertErrorResponse(t, status, got, errBody, http.StatusUnauthorized, string(dErrors.CodeUnauthorized))
	})

	s.T().Run("internal server failure - 500", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().UserInfo(gomock.Any(), validSessionID.String()).Return(nil, errors.New("database error"))

		status, got, errBody := s.doUserInfoRequest(t, router, validSessionID.String())

		s.assertErrorResponse(t, status, got, errBody, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})
}

func (s *AuthHandlerSuite) TestHandler_ListSessions() {
	userID := id.UserID(uuid.New())
	currentSessionID := id.SessionID(uuid.New())

	s.T().Run("invalid user id in context - 401", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().ListSessions(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		status, got, errBody := s.doListSessionsRequest(t, router, "not-a-uuid", currentSessionID.String())
		s.assertErrorResponse(t, status, got, errBody, http.StatusUnauthorized, string(dErrors.CodeUnauthorized))
	})

	s.T().Run("invalid session id in context - 401", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().ListSessions(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		status, got, errBody := s.doListSessionsRequest(t, router, userID.String(), "not-a-uuid")
		s.assertErrorResponse(t, status, got, errBody, http.StatusUnauthorized, string(dErrors.CodeUnauthorized))
	})

	s.T().Run("service error - 500", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().
			ListSessions(gomock.Any(), userID, currentSessionID).
			Return(nil, errors.New("boom"))

		status, got, errBody := s.doListSessionsRequest(t, router, userID.String(), currentSessionID.String())
		s.assertErrorResponse(t, status, got, errBody, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})
}

func (s *AuthHandlerSuite) TestHandler_RevokeSession() {
	userID := id.UserID(uuid.New())
	sessionID := id.SessionID(uuid.New())
	path := "/auth/sessions/" + sessionID.String()

	s.T().Run("invalid user id in context - 401", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().RevokeSession(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		status, got, errBody := s.doRevokeSessionRequest(t, router, path, "not-a-uuid")
		s.assertErrorResponse(t, status, got, errBody, http.StatusUnauthorized, string(dErrors.CodeUnauthorized))
	})

	s.T().Run("invalid session id in path - 400", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().RevokeSession(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		status, got, errBody := s.doRevokeSessionRequest(t, router, "/auth/sessions/not-a-uuid", userID.String())
		s.assertErrorResponse(t, status, got, errBody, http.StatusBadRequest, string(dErrors.CodeBadRequest))
	})
}

func (s *AuthHandlerSuite) TestHandler_LogoutAll() {
	userID := id.UserID(uuid.New())
	currentSessionID := id.SessionID(uuid.New())

	s.T().Run("invalid user id in context - 401", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().LogoutAll(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		status, _, errBody := s.doLogoutAllRequest(t, router, "not-a-uuid", currentSessionID.String(), "true")
		s.assertErrorResponse(t, status, nil, errBody, http.StatusUnauthorized, string(dErrors.CodeUnauthorized))
	})

	s.T().Run("invalid session id in context - 401", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().LogoutAll(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		status, _, errBody := s.doLogoutAllRequest(t, router, userID.String(), "not-a-uuid", "true")
		s.assertErrorResponse(t, status, nil, errBody, http.StatusUnauthorized, string(dErrors.CodeUnauthorized))
	})

	s.T().Run("service error - 500", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().
			LogoutAll(gomock.Any(), userID, currentSessionID, true).
			Return(nil, errors.New("boom"))

		status, _, errBody := s.doLogoutAllRequest(t, router, userID.String(), currentSessionID.String(), "true")
		s.assertErrorResponse(t, status, nil, errBody, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})

	s.T().Run("except_current=false parsed correctly", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().
			LogoutAll(gomock.Any(), userID, currentSessionID, false).
			Return(&models.LogoutAllResult{RevokedCount: 1}, nil)

		status, res, _ := s.doLogoutAllRequest(t, router, userID.String(), currentSessionID.String(), "false")
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, float64(1), res["revoked_count"])
	})
}

func (s *AuthHandlerSuite) TestHandler_AdminDeleteUser() {
	userID := id.UserID(uuid.New())
	validPath := "/admin/auth/users/" + userID.String()

	s.T().Run("invalid user id", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockService := mocks.NewMockService(ctrl)
		logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
		handler := New(mockService, nil, nil, logger, "__Secure-Device-ID", 31536000)

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
		handler := New(mockService, nil, nil, logger, "__Secure-Device-ID", 31536000)

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

func (s *AuthHandlerSuite) newHandler(t *testing.T) (*mocks.MockService, *chi.Mux) {
	t.Helper()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	mockService := mocks.NewMockService(ctrl)
	handler := New(mockService, nil, nil, logger, "__Secure-Device-ID", 31536000)
	r := chi.NewRouter()
	handler.Register(r)
	return mockService, r
}

func (s *AuthHandlerSuite) doUserInfoRequest(t *testing.T, router *chi.Mux, sessionID string) (int, *models.UserInfoResult, map[string]string) {
	t.Helper()
	httpReq := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)

	// Inject session ID into context (simulating what the auth middleware would do)
	if sessionID != "" {
		ctx := httpReq.Context()
		ctx = context.WithValue(ctx, authmw.ContextKeySessionID, sessionID)
		httpReq = httpReq.WithContext(ctx)
	}

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httpReq)

	raw, err := io.ReadAll(rr.Body)
	require.NoError(t, err)

	if rr.Code == http.StatusOK {
		var res models.UserInfoResult
		require.NoError(t, json.Unmarshal(raw, &res))
		return rr.Code, &res, nil
	} else {
		var errBody map[string]string
		require.NoError(t, json.Unmarshal(raw, &errBody))
		return rr.Code, nil, errBody
	}
}

func (s *AuthHandlerSuite) doListSessionsRequest(t *testing.T, router *chi.Mux, userID string, sessionID string) (int, *models.SessionsResult, map[string]string) {
	t.Helper()
	httpReq := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)

	ctx := httpReq.Context()
	if userID != "" {
		ctx = context.WithValue(ctx, authmw.ContextKeyUserID, userID)
	}
	if sessionID != "" {
		ctx = context.WithValue(ctx, authmw.ContextKeySessionID, sessionID)
	}
	httpReq = httpReq.WithContext(ctx)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httpReq)

	raw, err := io.ReadAll(rr.Body)
	require.NoError(t, err)

	if rr.Code == http.StatusOK {
		var res models.SessionsResult
		require.NoError(t, json.Unmarshal(raw, &res))
		return rr.Code, &res, nil
	}

	var errBody map[string]string
	require.NoError(t, json.Unmarshal(raw, &errBody))
	return rr.Code, nil, errBody
}

func (s *AuthHandlerSuite) doRevokeSessionRequest(t *testing.T, router *chi.Mux, path string, userID string) (int, *models.SessionRevocationResult, map[string]string) {
	t.Helper()
	httpReq := httptest.NewRequest(http.MethodDelete, path, nil)

	ctx := httpReq.Context()
	if userID != "" {
		ctx = context.WithValue(ctx, authmw.ContextKeyUserID, userID)
	}
	httpReq = httpReq.WithContext(ctx)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httpReq)

	raw, err := io.ReadAll(rr.Body)
	require.NoError(t, err)

	if rr.Code == http.StatusOK {
		var res models.SessionRevocationResult
		require.NoError(t, json.Unmarshal(raw, &res))
		return rr.Code, &res, nil
	}

	var errBody map[string]string
	require.NoError(t, json.Unmarshal(raw, &errBody))
	return rr.Code, nil, errBody
}

func (s *AuthHandlerSuite) doLogoutAllRequest(t *testing.T, router *chi.Mux, userID string, sessionID string, exceptCurrent string) (int, map[string]any, map[string]string) {
	t.Helper()
	path := "/auth/logout-all?except_current=" + exceptCurrent
	httpReq := httptest.NewRequest(http.MethodPost, path, nil)

	ctx := httpReq.Context()
	if userID != "" {
		ctx = context.WithValue(ctx, authmw.ContextKeyUserID, userID)
	}
	if sessionID != "" {
		ctx = context.WithValue(ctx, authmw.ContextKeySessionID, sessionID)
	}
	httpReq = httpReq.WithContext(ctx)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httpReq)

	raw, err := io.ReadAll(rr.Body)
	require.NoError(t, err)

	if rr.Code == http.StatusOK {
		var res map[string]any
		require.NoError(t, json.Unmarshal(raw, &res))
		return rr.Code, res, nil
	}

	var errBody map[string]string
	require.NoError(t, json.Unmarshal(raw, &errBody))
	return rr.Code, nil, errBody
}

func (s *AuthHandlerSuite) doAuthRequest(t *testing.T, router *chi.Mux, body string) (int, *models.AuthorizationResult, map[string]string) {
	t.Helper()
	httpReq := httptest.NewRequest(http.MethodPost, "/auth/authorize", strings.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, httpReq)

	raw, err := io.ReadAll(rr.Body)
	require.NoError(t, err)

	if rr.Code == http.StatusOK {
		var res models.AuthorizationResult
		require.NoError(t, json.Unmarshal(raw, &res))
		return rr.Code, &res, nil
	} else {
		var errBody map[string]string
		require.NoError(t, json.Unmarshal(raw, &errBody))
		return rr.Code, nil, errBody
	}
}

func (s *AuthHandlerSuite) doTokenRequest(t *testing.T, router *chi.Mux, body string) (int, *models.TokenResult, map[string]string) {
	t.Helper()
	httpReq := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, httpReq)
	raw, err := io.ReadAll(rr.Body)
	require.NoError(t, err)

	if rr.Code == http.StatusOK {
		var res models.TokenResult
		require.NoError(t, json.Unmarshal(raw, &res))
		return rr.Code, &res, nil
	} else {
		var errBody map[string]string
		require.NoError(t, json.Unmarshal(raw, &errBody))
		return rr.Code, nil, errBody
	}
}

func (s *AuthHandlerSuite) doTokenRequestRaw(t *testing.T, router *chi.Mux, body string) (int, *models.TokenResult, map[string]string, map[string]any) {
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
