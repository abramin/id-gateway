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

// HandlerSuite provides shared test setup for rate limit handler tests.
//
// Per AGENTS.md + testing.md:
// - "No behavior should be tested at multiple layers" - feature tests win
// - Handler tests only for edge cases unreachable via e2e (invalid JSON parsing)
// - E2E coverage: ratelimit.feature covers all valid request scenarios
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

// =============================================================================
// Invalid JSON Tests - Edge cases unreachable via E2E
//
// Per AGENTS.md: "Handlers handle HTTP concerns only: parsing, request validation"
// E2E tests use json.Marshal which always produces valid JSON.
// These tests verify the HTTP boundary handles malformed input correctly.
// =============================================================================

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
