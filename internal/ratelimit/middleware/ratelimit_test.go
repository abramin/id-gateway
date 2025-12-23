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
	checkIPErr        error
	checkIPResult     *models.RateLimitResult
	checkUserErr      error
	checkUserResult   *models.RateLimitResult
	checkBothErr      error
	checkBothResult   *models.RateLimitResult
	checkAuthErr      error
	checkAuthResult   *models.AuthRateLimitResult
	checkGlobalErr    error
	checkGlobalResult bool
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

// =============================================================================
// Circuit Breaker Tests (PRD-017 FR-7)
// =============================================================================
func (s *MiddlewareSecuritySuite) TestCircuitBreaker() {
	s.Run("circuit breaker opens after consecutive failures", func() {
		// Setup: Rate limiter that always fails
		failCount := 0
		limiter := &mockRateLimiter{
			checkIPErr: errors.New("store unavailable"),
		}

		// Track circuit state - expect circuit breaker to track failures
		middleware := New(limiter, s.logger)

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		// Make 5 consecutive failing requests (threshold from FR-7)
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			ctx := metadata.WithClientMetadata(req.Context(), "192.168.1.1", "test-agent")
			req = req.WithContext(ctx)
			rr := httptest.NewRecorder()

			handler := middleware.RateLimit(models.ClassRead)(next)
			handler.ServeHTTP(rr, req)
			failCount++
		}

		// After threshold, circuit should be open
		// The middleware should indicate degraded mode
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := metadata.WithClientMetadata(req.Context(), "192.168.1.1", "test-agent")
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()

		handler := middleware.RateLimit(models.ClassRead)(next)
		handler.ServeHTTP(rr, req)

		// PRD-017 FR-7: When circuit breaker is open, should indicate degraded status
		s.Equal("degraded", rr.Header().Get("X-RateLimit-Status"),
			"circuit breaker should indicate degraded status after threshold failures")
	})

	s.Run("circuit breaker uses in-memory fallback when open", func() {
		// Setup: Middleware with circuit breaker that has opened
		limiter := &mockRateLimiter{
			checkIPErr: errors.New("store unavailable"),
		}

		middleware := New(limiter, s.logger)

		// Trigger circuit breaker open state (5 failures)
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			ctx := metadata.WithClientMetadata(req.Context(), "192.168.1.1", "test-agent")
			req = req.WithContext(ctx)
			rr := httptest.NewRecorder()
			handler := middleware.RateLimit(models.ClassRead)(next)
			handler.ServeHTTP(rr, req)
		}

		// Now make requests - should use in-memory fallback
		// Requests should still have rate limit enforcement via fallback
		for i := 0; i < 15; i++ {
			req := httptest.NewRequest(http.MethodGet, "/auth/authorize", nil)
			ctx := metadata.WithClientMetadata(req.Context(), "192.168.1.1", "test-agent")
			req = req.WithContext(ctx)
			rr := httptest.NewRecorder()
			handler := middleware.RateLimit(models.ClassAuth)(next)
			handler.ServeHTTP(rr, req)
		}

		// After exceeding in-memory limit (10 for auth), should block
		req := httptest.NewRequest(http.MethodGet, "/auth/authorize", nil)
		ctx := metadata.WithClientMetadata(req.Context(), "192.168.1.1", "test-agent")
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()
		handler := middleware.RateLimit(models.ClassAuth)(next)
		handler.ServeHTTP(rr, req)

		// PRD-017 FR-7: In-memory fallback should still enforce rate limits
		s.Equal(http.StatusTooManyRequests, rr.Code,
			"in-memory fallback should enforce rate limits when circuit breaker is open")
	})

	s.Run("circuit breaker closes after successful probes", func() {
		// This test verifies the half-open state behavior
		successfulProbes := 0
		limiter := &mockRateLimiter{}

		// Start with failures to open circuit
		limiter.checkIPErr = errors.New("store unavailable")

		middleware := New(limiter, s.logger)

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		// Open the circuit with 5 failures
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			ctx := metadata.WithClientMetadata(req.Context(), "192.168.1.1", "test-agent")
			req = req.WithContext(ctx)
			rr := httptest.NewRecorder()
			handler := middleware.RateLimit(models.ClassRead)(next)
			handler.ServeHTTP(rr, req)
		}

		// Now fix the limiter (simulating Redis recovery)
		limiter.checkIPErr = nil
		limiter.checkIPResult = &models.RateLimitResult{
			Allowed:   true,
			Limit:     100,
			Remaining: 99,
		}

		// Make successful requests - circuit should eventually close
		for i := 0; i < 3; i++ { // 3 successful probes threshold
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			ctx := metadata.WithClientMetadata(req.Context(), "192.168.1.1", "test-agent")
			req = req.WithContext(ctx)
			rr := httptest.NewRecorder()
			handler := middleware.RateLimit(models.ClassRead)(next)
			handler.ServeHTTP(rr, req)
			if rr.Header().Get("X-RateLimit-Status") != "degraded" {
				successfulProbes++
			}
		}

		// After successful probes, circuit should be closed
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := metadata.WithClientMetadata(req.Context(), "192.168.1.1", "test-agent")
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()
		handler := middleware.RateLimit(models.ClassRead)(next)
		handler.ServeHTTP(rr, req)

		// PRD-017 FR-7: Circuit should close after successful probes
		s.Empty(rr.Header().Get("X-RateLimit-Status"),
			"circuit breaker should close after successful probes (no degraded status)")
		s.Equal("100", rr.Header().Get("X-RateLimit-Limit"),
			"should use primary store limits when circuit is closed")
	})
}
