package handler

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"credo/internal/ratelimit/admin"
	"credo/internal/ratelimit/store/allowlist"
	"credo/internal/ratelimit/store/bucket"
)

// HandlerSuite provides shared test setup for rate limit handler tests.
//
// Per AGENTS.md + testing.md:
// - "No behavior should be tested at multiple layers" - feature tests win
// - Handler tests only for edge cases unreachable via e2e (invalid JSON parsing)
// - E2E coverage: ratelimit.feature covers all valid request scenarios
type HandlerSuite struct {
	suite.Suite
	router http.Handler
}

func (s *HandlerSuite) SetupTest() {
	// Use real in-memory stores - no mocks per AGENTS.md
	buckets := bucket.New()
	allowlistStore := allowlist.New()

	adminSvc, err := admin.New(allowlistStore, buckets)
	require.NoError(s.T(), err)

	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	h := New(adminSvc, logger)

	r := chi.NewRouter()
	h.RegisterAdmin(r)
	s.router = r
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
