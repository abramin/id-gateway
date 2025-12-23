package middleware

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/suite"

	"credo/internal/ratelimit/models"
	"credo/pkg/platform/middleware/metadata"
)

// =============================================================================
// Rate Limit Middleware Security Test Suite
// =============================================================================
// Justification: Security tests verify fail-open behavior and ensure rate limiting
// middleware behaves predictably under error conditions.

type MiddlewareSecuritySuite struct {
	suite.Suite
	logger *slog.Logger
}

func TestMiddlewareSecuritySuite(t *testing.T) {
	suite.Run(t, new(MiddlewareSecuritySuite))
}

func (s *MiddlewareSecuritySuite) SetupTest() {
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
}

// =============================================================================
// Mock Rate Limiter for Testing
// =============================================================================

type mockRateLimiter struct {
	checkIPErr          error
	checkIPResult       *models.RateLimitResult
	checkUserErr        error
	checkUserResult     *models.RateLimitResult
	checkBothErr        error
	checkBothResult     *models.RateLimitResult
	checkAuthErr        error
	checkAuthResult     *models.AuthRateLimitResult
	checkGlobalErr      error
	checkGlobalResult   bool
}

func (m *mockRateLimiter) CheckIPRateLimit(_ context.Context, _ string, _ models.EndpointClass) (*models.RateLimitResult, error) {
	return m.checkIPResult, m.checkIPErr
}

func (m *mockRateLimiter) CheckUserRateLimit(_ context.Context, _ string, _ models.EndpointClass) (*models.RateLimitResult, error) {
	return m.checkUserResult, m.checkUserErr
}

func (m *mockRateLimiter) CheckBothLimits(_ context.Context, _, _ string, _ models.EndpointClass) (*models.RateLimitResult, error) {
	return m.checkBothResult, m.checkBothErr
}

func (m *mockRateLimiter) CheckAuthRateLimit(_ context.Context, _, _ string) (*models.AuthRateLimitResult, error) {
	return m.checkAuthResult, m.checkAuthErr
}

func (m *mockRateLimiter) CheckGlobalThrottle(_ context.Context) (bool, error) {
	return m.checkGlobalResult, m.checkGlobalErr
}

// =============================================================================
// Fail-Open Bypass Tests (Security)
// =============================================================================
// Security test: Verify behavior when bucket store returns errors.
// Current documented behavior: fail-open (bypass rate limiting).
// This test documents the current behavior for security awareness.

func (s *MiddlewareSecuritySuite) TestFailOpenBehavior() {
	s.Run("IP rate limit check error bypasses limiting (fail-open)", func() {
		// Setup: Rate limiter returns an error
		limiter := &mockRateLimiter{
			checkIPErr: errors.New("store unavailable"),
		}
		middleware := New(limiter, s.logger)

		// Track if next handler was called
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		// Create request with client IP in context
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := metadata.WithClientMetadata(req.Context(), "192.168.1.1", "test-agent")
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		// Execute middleware
		handler := middleware.RateLimit(models.ClassRead)(next)
		handler.ServeHTTP(rr, req)

		// DOCUMENTED BEHAVIOR: Request proceeds (fail-open)
		s.True(nextCalled, "fail-open: next handler should be called when rate limit check fails")
		s.Equal(http.StatusOK, rr.Code, "fail-open: request should succeed")
	})

	s.Run("authenticated rate limit check error bypasses limiting (fail-open)", func() {
		limiter := &mockRateLimiter{
			checkBothErr: errors.New("store unavailable"),
		}
		middleware := New(limiter, s.logger)

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := metadata.WithClientMetadata(req.Context(), "192.168.1.1", "test-agent")
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		handler := middleware.RateLimitAuthenticated(models.ClassRead)(next)
		handler.ServeHTTP(rr, req)

		// DOCUMENTED BEHAVIOR: Request proceeds (fail-open)
		s.True(nextCalled, "fail-open: next handler should be called when rate limit check fails")
		s.Equal(http.StatusOK, rr.Code, "fail-open: request should succeed")
	})

	s.Run("global throttle check error bypasses limiting (fail-open)", func() {
		limiter := &mockRateLimiter{
			checkGlobalErr: errors.New("store unavailable"),
		}
		middleware := New(limiter, s.logger)

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rr := httptest.NewRecorder()

		handler := middleware.GlobalThrottle()(next)
		handler.ServeHTTP(rr, req)

		// DOCUMENTED BEHAVIOR: Request proceeds (fail-open)
		s.True(nextCalled, "fail-open: next handler should be called when global throttle check fails")
		s.Equal(http.StatusOK, rr.Code, "fail-open: request should succeed")
	})
}

// =============================================================================
// Normal Operation Tests
// =============================================================================

func (s *MiddlewareSecuritySuite) TestNormalOperation() {
	s.Run("allowed request proceeds", func() {
		limiter := &mockRateLimiter{
			checkIPResult: &models.RateLimitResult{
				Allowed:   true,
				Limit:     100,
				Remaining: 99,
			},
		}
		middleware := New(limiter, s.logger)

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := metadata.WithClientMetadata(req.Context(), "192.168.1.1", "test-agent")
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		handler := middleware.RateLimit(models.ClassRead)(next)
		handler.ServeHTTP(rr, req)

		s.True(nextCalled)
		s.Equal(http.StatusOK, rr.Code)
		s.Equal("100", rr.Header().Get("X-RateLimit-Limit"))
		s.Equal("99", rr.Header().Get("X-RateLimit-Remaining"))
	})

	s.Run("blocked request returns 429", func() {
		limiter := &mockRateLimiter{
			checkIPResult: &models.RateLimitResult{
				Allowed:    false,
				Limit:      100,
				Remaining:  0,
				RetryAfter: 60,
			},
		}
		middleware := New(limiter, s.logger)

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := metadata.WithClientMetadata(req.Context(), "192.168.1.1", "test-agent")
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		handler := middleware.RateLimit(models.ClassRead)(next)
		handler.ServeHTTP(rr, req)

		s.False(nextCalled, "next handler should not be called when rate limited")
		s.Equal(http.StatusTooManyRequests, rr.Code)
		s.Equal("60", rr.Header().Get("Retry-After"))
	})

	s.Run("disabled middleware allows all requests", func() {
		limiter := &mockRateLimiter{
			checkIPResult: &models.RateLimitResult{
				Allowed: false, // Would block if enabled
			},
		}
		middleware := New(limiter, s.logger, WithDisabled(true))

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rr := httptest.NewRecorder()

		handler := middleware.RateLimit(models.ClassRead)(next)
		handler.ServeHTTP(rr, req)

		s.True(nextCalled, "disabled middleware should allow all requests")
		s.Equal(http.StatusOK, rr.Code)
	})
}
