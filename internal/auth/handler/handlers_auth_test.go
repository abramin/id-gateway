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

func (s *AuthHandlerSuite) TestAuthorizeHandler_ErrorMapping() {
	var validRequest = &models.AuthorizationRequest{
		Email:       "user@example.com",
		ClientID:    "test-client-id",
		Scopes:      []string{"scope1", "scope2"},
		RedirectURI: "https://example.com/redirect",
		State:       "test-state",
	}

	s.Run("returns 500 when service fails", func() {
		mockService, router := s.newHandler()
		mockService.EXPECT().Authorize(gomock.Any(), validRequest).Return(nil, errors.New("boom"))

		status, got, errBody := s.doAuthRequest(router, s.mustMarshal(validRequest))

		s.assertErrorResponse(status, got, errBody, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})
}

func (s *AuthHandlerSuite) TestTokenHandler_ResponseShapeAndErrors() {
	validRequest := &models.TokenRequest{
		GrantType:   string(models.GrantAuthorizationCode),
		Code:        "authz_code_123",
		RedirectURI: "https://example.com/callback",
		ClientID:    "some-client-id",
	}

	s.Run("token response includes token_type", func() {
		mockService, router := s.newHandler()
		expectedResp := &models.TokenResult{
			AccessToken: "access-token-123",
			IDToken:     "id-token-123",
			ExpiresIn:   3600,
			TokenType:   "Bearer",
		}
		mockService.EXPECT().Token(gomock.Any(), gomock.Any()).Return(expectedResp, nil)

		status, _, errBody, raw := s.doTokenRequestRaw(router, s.mustMarshal(validRequest))

		s.assertSuccessResponse(status, raw, errBody)
		s.Require().Contains(raw, "token_type")
		s.Equal("Bearer", raw["token_type"])
	})

	s.Run("internal server failure - 500", func() {
		mockService, router := s.newHandler()
		mockService.EXPECT().Token(gomock.Any(), gomock.Any()).Return(nil, errors.New("database error"))
		status, got, errBody := s.doTokenRequest(router, s.mustMarshal(validRequest))

		s.assertErrorResponse(status, got, errBody, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})
}

func (s *AuthHandlerSuite) TestUserInfoHandler_ContextValidation() {
	validSessionID := uuid.New()

	s.Run("missing session id in context - 401", func() {
		_, router := s.newHandler()
		// Service should NOT be called - handler validates session before calling service

		status, got, errBody := s.doUserInfoRequest(router, "")

		s.assertErrorResponse(status, got, errBody, http.StatusUnauthorized, string(dErrors.CodeUnauthorized))
	})

	s.Run("invalid session id in context - 401", func() {
		_, router := s.newHandler()
		// Service should NOT be called - invalid session ID won't be injected into context

		status, got, errBody := s.doUserInfoRequest(router, "not-a-uuid")

		s.assertErrorResponse(status, got, errBody, http.StatusUnauthorized, string(dErrors.CodeUnauthorized))
	})

	s.Run("internal server failure - 500", func() {
		mockService, router := s.newHandler()
		mockService.EXPECT().UserInfo(gomock.Any(), validSessionID.String()).Return(nil, errors.New("database error"))

		status, got, errBody := s.doUserInfoRequest(router, validSessionID.String())

		s.assertErrorResponse(status, got, errBody, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})
}

func (s *AuthHandlerSuite) TestSessionsHandler_ContextValidation() {
	userID := id.UserID(uuid.New())
	currentSessionID := id.SessionID(uuid.New())

	s.Run("invalid user id in context - 401", func() {
		mockService, router := s.newHandler()
		mockService.EXPECT().ListSessions(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		status, got, errBody := s.doListSessionsRequest(router, "not-a-uuid", currentSessionID.String())
		s.assertErrorResponse(status, got, errBody, http.StatusUnauthorized, string(dErrors.CodeUnauthorized))
	})

	s.Run("invalid session id in context - 401", func() {
		mockService, router := s.newHandler()
		mockService.EXPECT().ListSessions(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		status, got, errBody := s.doListSessionsRequest(router, userID.String(), "not-a-uuid")
		s.assertErrorResponse(status, got, errBody, http.StatusUnauthorized, string(dErrors.CodeUnauthorized))
	})

	s.Run("service error - 500", func() {
		mockService, router := s.newHandler()
		mockService.EXPECT().
			ListSessions(gomock.Any(), userID, currentSessionID).
			Return(nil, errors.New("boom"))

		status, got, errBody := s.doListSessionsRequest(router, userID.String(), currentSessionID.String())
		s.assertErrorResponse(status, got, errBody, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})
}

func (s *AuthHandlerSuite) TestSessionRevocationHandler_ContextValidation() {
	userID := id.UserID(uuid.New())
	sessionID := id.SessionID(uuid.New())
	path := "/auth/sessions/" + sessionID.String()

	s.Run("invalid user id in context - 401", func() {
		mockService, router := s.newHandler()
		mockService.EXPECT().RevokeSession(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		status, got, errBody := s.doRevokeSessionRequest(router, path, "not-a-uuid")
		s.assertErrorResponse(status, got, errBody, http.StatusUnauthorized, string(dErrors.CodeUnauthorized))
	})

	s.Run("invalid session id in path - 400", func() {
		mockService, router := s.newHandler()
		mockService.EXPECT().RevokeSession(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		status, got, errBody := s.doRevokeSessionRequest(router, "/auth/sessions/not-a-uuid", userID.String())
		s.assertErrorResponse(status, got, errBody, http.StatusBadRequest, string(dErrors.CodeBadRequest))
	})
}

func (s *AuthHandlerSuite) TestLogoutAllHandler_ContextValidation() {
	userID := id.UserID(uuid.New())
	currentSessionID := id.SessionID(uuid.New())

	s.Run("invalid user id in context - 401", func() {
		mockService, router := s.newHandler()
		mockService.EXPECT().LogoutAll(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		status, _, errBody := s.doLogoutAllRequest(router, "not-a-uuid", currentSessionID.String(), "true")
		s.assertErrorResponse(status, nil, errBody, http.StatusUnauthorized, string(dErrors.CodeUnauthorized))
	})

	s.Run("invalid session id in context - 401", func() {
		mockService, router := s.newHandler()
		mockService.EXPECT().LogoutAll(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

		status, _, errBody := s.doLogoutAllRequest(router, userID.String(), "not-a-uuid", "true")
		s.assertErrorResponse(status, nil, errBody, http.StatusUnauthorized, string(dErrors.CodeUnauthorized))
	})

	s.Run("service error - 500", func() {
		mockService, router := s.newHandler()
		mockService.EXPECT().
			LogoutAll(gomock.Any(), userID, currentSessionID, true).
			Return(nil, errors.New("boom"))

		status, _, errBody := s.doLogoutAllRequest(router, userID.String(), currentSessionID.String(), "true")
		s.assertErrorResponse(status, nil, errBody, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})

	s.Run("except_current=false parsed correctly", func() {
		mockService, router := s.newHandler()
		mockService.EXPECT().
			LogoutAll(gomock.Any(), userID, currentSessionID, false).
			Return(&models.LogoutAllResult{RevokedCount: 1}, nil)

		status, res, _ := s.doLogoutAllRequest(router, userID.String(), currentSessionID.String(), "false")
		s.Equal(http.StatusOK, status)
		s.Equal(float64(1), res["revoked_count"])
	})
}

func (s *AuthHandlerSuite) TestAdminDeleteUserHandler_Validation() {
	userID := id.UserID(uuid.New())
	validPath := "/admin/auth/users/" + userID.String()

	s.Run("invalid user id", func() {
		t := s.T()
		ctrl := gomock.NewController(t)
		mockService := mocks.NewMockService(ctrl)
		logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
		handler := New(mockService, nil, nil, logger, "__Secure-Device-ID", 31536000)

		r := chi.NewRouter()
		handler.RegisterAdmin(r)

		req := httptest.NewRequest(http.MethodDelete, "/admin/auth/users/not-a-uuid", nil)
		recorder := httptest.NewRecorder()

		r.ServeHTTP(recorder, req)

		s.Equal(http.StatusBadRequest, recorder.Code)
	})

	s.Run("service error", func() {
		t := s.T()
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

		s.Equal(http.StatusInternalServerError, recorder.Code)
	})
}

func TestAuthHandlerSuite(t *testing.T) {
	suite.Run(t, new(AuthHandlerSuite))
}

func (s *AuthHandlerSuite) newHandler() (*mocks.MockService, *chi.Mux) {
	t := s.T()
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

func (s *AuthHandlerSuite) doUserInfoRequest(router *chi.Mux, sessionID string) (int, *models.UserInfoResult, map[string]string) {
	s.T().Helper()
	httpReq := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)

	// Inject session ID into context (simulating what the auth middleware would do)
	// Only inject if it parses to a valid typed ID (mirrors real middleware behavior)
	if sessionID != "" {
		if parsedSessionID, err := id.ParseSessionID(sessionID); err == nil {
			ctx := httpReq.Context()
			ctx = context.WithValue(ctx, authmw.ContextKeySessionID, parsedSessionID)
			httpReq = httpReq.WithContext(ctx)
		}
	}

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httpReq)

	raw, err := io.ReadAll(rr.Body)
	s.Require().NoError(err)

	if rr.Code == http.StatusOK {
		var res models.UserInfoResult
		s.Require().NoError(json.Unmarshal(raw, &res))
		return rr.Code, &res, nil
	} else {
		var errBody map[string]string
		s.Require().NoError(json.Unmarshal(raw, &errBody))
		return rr.Code, nil, errBody
	}
}

func (s *AuthHandlerSuite) doListSessionsRequest(router *chi.Mux, userID string, sessionID string) (int, *models.SessionsResult, map[string]string) {
	s.T().Helper()
	httpReq := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)

	// Inject typed IDs into context (simulating what the auth middleware would do)
	// Only inject if they parse to valid typed IDs (mirrors real middleware behavior)
	ctx := httpReq.Context()
	if userID != "" {
		if parsedUserID, err := id.ParseUserID(userID); err == nil {
			ctx = context.WithValue(ctx, authmw.ContextKeyUserID, parsedUserID)
		}
	}
	if sessionID != "" {
		if parsedSessionID, err := id.ParseSessionID(sessionID); err == nil {
			ctx = context.WithValue(ctx, authmw.ContextKeySessionID, parsedSessionID)
		}
	}
	httpReq = httpReq.WithContext(ctx)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httpReq)

	raw, err := io.ReadAll(rr.Body)
	s.Require().NoError(err)

	if rr.Code == http.StatusOK {
		var res models.SessionsResult
		s.Require().NoError(json.Unmarshal(raw, &res))
		return rr.Code, &res, nil
	}

	var errBody map[string]string
	s.Require().NoError(json.Unmarshal(raw, &errBody))
	return rr.Code, nil, errBody
}

func (s *AuthHandlerSuite) doRevokeSessionRequest(router *chi.Mux, path string, userID string) (int, *models.SessionRevocationResult, map[string]string) {
	s.T().Helper()
	httpReq := httptest.NewRequest(http.MethodDelete, path, nil)

	// Inject typed IDs into context (simulating what the auth middleware would do)
	// Only inject if they parse to valid typed IDs (mirrors real middleware behavior)
	ctx := httpReq.Context()
	if userID != "" {
		if parsedUserID, err := id.ParseUserID(userID); err == nil {
			ctx = context.WithValue(ctx, authmw.ContextKeyUserID, parsedUserID)
		}
	}
	httpReq = httpReq.WithContext(ctx)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httpReq)

	raw, err := io.ReadAll(rr.Body)
	s.Require().NoError(err)

	if rr.Code == http.StatusOK {
		var res models.SessionRevocationResult
		s.Require().NoError(json.Unmarshal(raw, &res))
		return rr.Code, &res, nil
	}

	var errBody map[string]string
	s.Require().NoError(json.Unmarshal(raw, &errBody))
	return rr.Code, nil, errBody
}

func (s *AuthHandlerSuite) doLogoutAllRequest(router *chi.Mux, userID string, sessionID string, exceptCurrent string) (int, map[string]any, map[string]string) {
	s.T().Helper()
	path := "/auth/logout-all?except_current=" + exceptCurrent
	httpReq := httptest.NewRequest(http.MethodPost, path, nil)

	// Inject typed IDs into context (simulating what the auth middleware would do)
	// Only inject if they parse to valid typed IDs (mirrors real middleware behavior)
	ctx := httpReq.Context()
	if userID != "" {
		if parsedUserID, err := id.ParseUserID(userID); err == nil {
			ctx = context.WithValue(ctx, authmw.ContextKeyUserID, parsedUserID)
		}
	}
	if sessionID != "" {
		if parsedSessionID, err := id.ParseSessionID(sessionID); err == nil {
			ctx = context.WithValue(ctx, authmw.ContextKeySessionID, parsedSessionID)
		}
	}
	httpReq = httpReq.WithContext(ctx)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httpReq)

	raw, err := io.ReadAll(rr.Body)
	s.Require().NoError(err)

	if rr.Code == http.StatusOK {
		var res map[string]any
		s.Require().NoError(json.Unmarshal(raw, &res))
		return rr.Code, res, nil
	}

	var errBody map[string]string
	s.Require().NoError(json.Unmarshal(raw, &errBody))
	return rr.Code, nil, errBody
}

func (s *AuthHandlerSuite) doAuthRequest(router *chi.Mux, body string) (int, *models.AuthorizationResult, map[string]string) {
	s.T().Helper()
	httpReq := httptest.NewRequest(http.MethodPost, "/auth/authorize", strings.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, httpReq)

	raw, err := io.ReadAll(rr.Body)
	s.Require().NoError(err)

	if rr.Code == http.StatusOK {
		var res models.AuthorizationResult
		s.Require().NoError(json.Unmarshal(raw, &res))
		return rr.Code, &res, nil
	} else {
		var errBody map[string]string
		s.Require().NoError(json.Unmarshal(raw, &errBody))
		return rr.Code, nil, errBody
	}
}

func (s *AuthHandlerSuite) doTokenRequest(router *chi.Mux, body string) (int, *models.TokenResult, map[string]string) {
	s.T().Helper()
	httpReq := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, httpReq)
	raw, err := io.ReadAll(rr.Body)
	s.Require().NoError(err)

	if rr.Code == http.StatusOK {
		var res models.TokenResult
		s.Require().NoError(json.Unmarshal(raw, &res))
		return rr.Code, &res, nil
	} else {
		var errBody map[string]string
		s.Require().NoError(json.Unmarshal(raw, &errBody))
		return rr.Code, nil, errBody
	}
}

func (s *AuthHandlerSuite) doTokenRequestRaw(router *chi.Mux, body string) (int, *models.TokenResult, map[string]string, map[string]any) {
	s.T().Helper()
	httpReq := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, httpReq)
	raw, err := io.ReadAll(rr.Body)
	s.Require().NoError(err)

	if rr.Code == http.StatusOK {
		var res map[string]any
		s.Require().NoError(json.Unmarshal(raw, &res))
		return rr.Code, nil, nil, res
	}

	var errBody map[string]string
	s.Require().NoError(json.Unmarshal(raw, &errBody))
	return rr.Code, nil, errBody, nil
}

func (s *AuthHandlerSuite) mustMarshal(v any) string {
	s.T().Helper()
	body, err := json.Marshal(v)
	s.Require().NoError(err)
	return string(body)
}

func (s *AuthHandlerSuite) assertErrorResponse(status int, got interface{}, errBody map[string]string, expectedStatus int, expectedCode string) {
	s.T().Helper()
	s.Equal(expectedStatus, status)
	s.Nil(got)
	s.Equal(expectedCode, errBody["error"])
}

func (s *AuthHandlerSuite) assertSuccessResponse(status int, got interface{}, errBody map[string]string) {
	s.T().Helper()
	s.Equal(http.StatusOK, status)
	s.NotNil(got)
	s.Nil(errBody)
}
