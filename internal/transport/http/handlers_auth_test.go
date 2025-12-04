package httptransport

import (
	"context"
	"encoding/json"
	"errors"
	"id-gateway/internal/transport/http/mocks"
	httpErrors "id-gateway/pkg/http-errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authModel "id-gateway/internal/auth/models"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

//go:generate mockgen -source=handlers_auth.go -destination=mocks/auth-mocks.go -package=mocks AuthService
type AuthHandlerSuite struct {
	suite.Suite
	handler     *AuthHandler
	ctx         context.Context
	router      *http.ServeMux
	mockService *mocks.MockAuthService
	ctrl        *gomock.Controller
}

func (s *AuthHandlerSuite) SetupSuite() {
	s.ctx = context.Background()
}

func (s *AuthHandlerSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.mockService = mocks.NewMockAuthService(s.ctrl)
	s.handler = NewAuthHandler(s.mockService)
	mux := http.NewServeMux()
	s.handler.Register(mux)
	s.router = mux
}

func (s *AuthHandlerSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *AuthHandlerSuite) TestService_Authorize() {
	var validRequest = &authModel.AuthorizationRequest{
		Email:       "user@example.com",
		ClientID:    "test-client-id",
		Scopes:      []string{"scope1", "scope2"},
		RedirectURI: "some-redirect-uri/",
		State:       "test-state",
	}
	s.T().Run("user is found and authorized - 200", func(t *testing.T) {
		expectedResp := &authModel.AuthorizationResult{
			SessionID:   "sess_12345",
			RedirectURI: "some-redirect-uri/",
		}
		s.mockService.EXPECT().Authorize(gomock.Any(), validRequest).Return(expectedResp, nil)

		status, got := s.doAuthRequest(s.mustMarshal(validRequest, t))

		s.Equal(http.StatusOK, status)
		s.Equal(expectedResp.SessionID, got["session_id"])
		s.Equal(expectedResp.RedirectURI, got["redirect_uri"])
	})

	s.T().Run("returns 400 when request is invalid", func(t *testing.T) {
		s.mockService.EXPECT().Authorize(gomock.Any(), gomock.Any()).Times(0)

		status, got := s.doAuthRequest("{bad-json")

		s.Equal(http.StatusBadRequest, status)
		s.Equal(string(httpErrors.CodeInvalidInput), got["error"])
	})

	s.T().Run("returns 500 when service fails", func(t *testing.T) {
		s.mockService.EXPECT().Authorize(gomock.Any(), validRequest).Return(nil, errors.New("boom"))

		status, got := s.doAuthRequest(s.mustMarshal(validRequest, t))

		s.Equal(http.StatusInternalServerError, status)
		s.Equal(string(httpErrors.CodeInternal), got["error"])
	})
}

func TestAuthHandlerSuite(t *testing.T) {
	suite.Run(t, new(AuthHandlerSuite))
}

func (s *AuthHandlerSuite) doAuthRequest(body string) (int, map[string]string) {
	httpReq := httptest.NewRequest(http.MethodPost, "/auth/authorize", strings.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	s.router.ServeHTTP(rr, httpReq)

	var got map[string]string
	s.Require().NoError(json.NewDecoder(rr.Body).Decode(&got))
	return rr.Code, got
}

func (s *AuthHandlerSuite) mustMarshal(v any, t *testing.T) string {
	body, err := json.Marshal(v)
	require.NoError(t, err)
	return string(body)
}
