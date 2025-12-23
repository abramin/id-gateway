package handler

//go:generate mockgen -source=handler.go -destination=mocks/handler_mock.go -package=mocks Service

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	"credo/internal/ratelimit/handler/mocks"
)

// =============================================================================
// Handler Test Suite
// =============================================================================
// Justification: These tests validate request parsing at the HTTP boundary.
// They ensure malformed JSON is rejected with 400 before reaching service layer.
// Full request→service→response flows are covered by E2E feature tests in
// e2e/features/ratelimit.feature (@admin, @allowlist scenarios).
// These tests may be removed once E2E step definitions are fully implemented.

type HandlerSuite struct {
	suite.Suite
	router      http.Handler
	ctrl        *gomock.Controller
	mockService *mocks.MockService
}

func (s *HandlerSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.mockService = mocks.NewMockService(s.ctrl)
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	h := New(s.mockService, logger)

	r := chi.NewRouter()
	h.RegisterAdmin(r)
	s.router = r
}

func (s *HandlerSuite) TearDownTest() {
	s.ctrl.Finish()
}

func TestHandlerSuite(t *testing.T) {
	suite.Run(t, new(HandlerSuite))
}

func (s *HandlerSuite) TestAddAllowlist_InvalidJSON() {
	req := httptest.NewRequest(http.MethodPost, "/admin/rate-limit/allowlist",
		bytes.NewReader([]byte("not valid json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.router.ServeHTTP(rec, req)

	assert.Equal(s.T(), http.StatusBadRequest, rec.Code,
		"expected 400 for invalid JSON")
}

func (s *HandlerSuite) TestRemoveAllowlist_InvalidJSON() {
	req := httptest.NewRequest(http.MethodDelete, "/admin/rate-limit/allowlist",
		bytes.NewReader([]byte("not valid json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.router.ServeHTTP(rec, req)

	assert.Equal(s.T(), http.StatusBadRequest, rec.Code,
		"expected 400 for invalid JSON")
}

func (s *HandlerSuite) TestResetRateLimit_InvalidJSON() {
	req := httptest.NewRequest(http.MethodPost, "/admin/rate-limit/reset",
		bytes.NewReader([]byte("not valid json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.router.ServeHTTP(rec, req)

	assert.Equal(s.T(), http.StatusBadRequest, rec.Code,
		"expected 400 for invalid JSON")
}
