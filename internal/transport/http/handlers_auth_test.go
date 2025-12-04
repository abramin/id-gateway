package httptransport

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

	authModel "id-gateway/internal/auth/models"
	"id-gateway/internal/transport/http/mocks"
	httpErrors "id-gateway/pkg/http-errors"
)

//go:generate mockgen -source=handlers_auth.go -destination=mocks/auth-mocks.go -package=mocks AuthService
type AuthHandlerSuite struct {
	suite.Suite
	handler     *AuthHandler
	ctx         context.Context
	router      chi.Router
	mockService *mocks.MockAuthService
	ctrl        *gomock.Controller
}

func (s *AuthHandlerSuite) SetupSuite() {
	s.ctx = context.Background()
}
func (s *AuthHandlerSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *AuthHandlerSuite) TestService_Authorize() {
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
			SessionID:   uuid.New(),
			RedirectURI: validRequest.RedirectURI,
		}
		mockService.EXPECT().Authorize(gomock.Any(), validRequest).Return(expectedResp, nil)

		status, got, errBody := s.doAuthRequest(t, router, s.mustMarshal(validRequest, t))

		assert.Equal(t, http.StatusOK, status)
		assert.NotNil(t, got)
		assert.Nil(t, errBody)
		assert.Equal(t, expectedResp.SessionID, got.SessionID)
		assert.Equal(t, expectedResp.RedirectURI, got.RedirectURI)
	})

	s.T().Run("returns 400 when request body is invalid json", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().Authorize(gomock.Any(), gomock.Any()).Times(0)

		status, got, errBody := s.doAuthRequest(t, router, "{bad-json")

		assert.Equal(t, http.StatusBadRequest, status)
		assert.Nil(t, got)
		assert.Equal(t, string(httpErrors.CodeInvalidInput), errBody["error"])
	})

	s.T().Run("returns 400 when email is invalid", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().Authorize(gomock.Any(), gomock.Any()).Times(0)
		invalid := *validRequest
		invalid.Email = "invalid-email"
		invalidEmailRequest := &invalid

		status, got, errBody := s.doAuthRequest(t, router, s.mustMarshal(invalidEmailRequest, t))

		assert.Equal(t, http.StatusBadRequest, status)
		assert.Nil(t, got)
		assert.Equal(t, string(httpErrors.CodeInvalidInput), errBody["error"])
	})

	s.T().Run("returns 400 when redirect URI is invalid", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().Authorize(gomock.Any(), gomock.Any()).Times(0)
		invalid := *validRequest
		invalid.RedirectURI = "invalid-uri"
		invalidRedirectURIRequest := &invalid

		status, got, errBody := s.doAuthRequest(t, router, s.mustMarshal(invalidRedirectURIRequest, t))

		assert.Equal(t, http.StatusBadRequest, status)
		assert.Nil(t, got)
		assert.Equal(t, string(httpErrors.CodeInvalidInput), errBody["error"])
	})

	s.T().Run("returns 400 when params missing", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().Authorize(gomock.Any(), gomock.Any()).Times(0)
		missing := *validRequest
		missing.ClientID = ""
		missingParamRequest := &missing

		status, got, errBody := s.doAuthRequest(t, router, s.mustMarshal(missingParamRequest, t))

		assert.Equal(t, http.StatusBadRequest, status)
		assert.Nil(t, got)
		assert.Equal(t, string(httpErrors.CodeInvalidInput), errBody["error"])
	})

	s.T().Run("returns 400 when scopes contain empty value", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().Authorize(gomock.Any(), gomock.Any()).Times(0)
		invalid := *validRequest
		invalid.Scopes = []string{"scope1", " "}

		status, got, errBody := s.doAuthRequest(t, router, s.mustMarshal(&invalid, t))

		assert.Equal(t, http.StatusBadRequest, status)
		assert.Nil(t, got)
		assert.Equal(t, string(httpErrors.CodeInvalidInput), errBody["error"])
	})

	s.T().Run("returns 400 when scopes list is empty", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().Authorize(gomock.Any(), gomock.Any()).Times(0)
		invalid := *validRequest
		invalid.Scopes = []string{}

		status, got, errBody := s.doAuthRequest(t, router, s.mustMarshal(&invalid, t))

		assert.Equal(t, http.StatusBadRequest, status)
		assert.Nil(t, got)
		assert.Equal(t, string(httpErrors.CodeInvalidInput), errBody["error"])
	})

	s.T().Run("returns 500 when service fails", func(t *testing.T) {
		mockService, router := s.newHandler(t)
		mockService.EXPECT().Authorize(gomock.Any(), validRequest).Return(nil, errors.New("boom"))

		status, got, errBody := s.doAuthRequest(t, router, s.mustMarshal(validRequest, t))

		assert.Equal(t, http.StatusInternalServerError, status)
		assert.Nil(t, got)
		assert.Equal(t, string(httpErrors.CodeInternal), errBody["error"])
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
	handler := NewAuthHandler(mockService, logger)
	r := chi.NewRouter()
	handler.Register(r)
	router := r
	return mockService, router
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

func (s *AuthHandlerSuite) mustMarshal(v any, t *testing.T) string {
	t.Helper()
	body, err := json.Marshal(v)
	require.NoError(t, err)
	return string(body)
}
