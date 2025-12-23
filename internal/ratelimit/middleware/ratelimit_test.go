package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"credo/internal/ratelimit/config"
	"credo/internal/ratelimit/models"
	"credo/internal/ratelimit/store/allowlist"
	authmw "credo/pkg/platform/middleware/auth"
	"credo/pkg/platform/middleware/metadata"
)

// =============================================================================
// Rate Limit Middleware Security Test Suite
// =============================================================================
// Justification: Security tests verify fail-open behavior and ensure rate limiting
// middleware behaves predictably under error conditions.

type MiddlewareSecuritySuite struct {
	suite.Suite
	logger            *slog.Logger
	fallback          RateLimiter
	fallbackAuthLimit int
}

func TestMiddlewareSecuritySuite(t *testing.T) {
	suite.Run(t, new(MiddlewareSecuritySuite))
}

func (s *MiddlewareSecuritySuite) SetupTest() {
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	fallbackConfig := &config.Config{
		IPLimits: map[models.EndpointClass]config.Limit{
			models.ClassAuth: {RequestsPerWindow: 3, Window: time.Minute},
			models.ClassRead: {RequestsPerWindow: 100, Window: time.Minute},
		},
		UserLimits: map[models.EndpointClass]config.Limit{
			models.ClassRead: {RequestsPerWindow: 50, Window: time.Hour},
		},
	}
	s.fallbackAuthLimit = fallbackConfig.IPLimits[models.ClassAuth].RequestsPerWindow
	s.fallback = NewFallbackLimiter(fallbackConfig, allowlist.New(), s.logger)
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

type mockClientLimiter struct {
	checkErr     error
	result       *models.RateLimitResult
	called       int
	lastClientID string
	lastEndpoint string
}

func (m *mockClientLimiter) Check(_ context.Context, clientID, endpoint string) (*models.RateLimitResult, error) {
	m.called++
	m.lastClientID = clientID
	m.lastEndpoint = endpoint
	return m.result, m.checkErr
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
		middleware := New(limiter, s.logger, WithFallbackLimiter(s.fallback))

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
		middleware := New(limiter, s.logger, WithFallbackLimiter(s.fallback))

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
		middleware := New(limiter, s.logger, WithFallbackLimiter(s.fallback))

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
		middleware := New(limiter, s.logger, WithFallbackLimiter(s.fallback))

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

	s.Run("authenticated blocked request returns user rate limit payload", func() {
		resetAt := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
		limiter := &mockRateLimiter{
			checkBothResult: &models.RateLimitResult{
				Allowed:    false,
				Limit:      5,
				Remaining:  0,
				RetryAfter: 120,
				ResetAt:    resetAt,
			},
		}
		middleware := New(limiter, s.logger, WithFallbackLimiter(s.fallback))

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := metadata.WithClientMetadata(req.Context(), "192.168.1.1", "test-agent")
		ctx = context.WithValue(ctx, authmw.ContextKeyUserID, "user-123")
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		handler := middleware.RateLimitAuthenticated(models.ClassRead)(next)
		handler.ServeHTTP(rr, req)

		s.False(nextCalled, "next handler should not be called when user rate limited")
		s.Equal(http.StatusTooManyRequests, rr.Code)
		s.Equal("120", rr.Header().Get("Retry-After"))

		var payload models.UserRateLimitExceededResponse
		err := json.Unmarshal(rr.Body.Bytes(), &payload)
		s.Require().NoError(err)
		s.Equal("user_rate_limit_exceeded", payload.Error)
		s.Equal(5, payload.QuotaLimit)
		s.Equal(0, payload.QuotaRemaining)
		s.True(payload.QuotaReset.Equal(resetAt))
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
		middleware := New(limiter, s.logger, WithFallbackLimiter(s.fallback))

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
		middleware := New(limiter, s.logger, WithDisabled(true), WithFallbackLimiter(s.fallback))

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
		middleware := New(limiter, s.logger, WithFallbackLimiter(s.fallback))

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		// Make 5 consecutive failing requests to trigger circuit breaker
		for range 5 {
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

		middleware := New(limiter, s.logger, WithFallbackLimiter(s.fallback))

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
		for i := 0; i < s.fallbackAuthLimit; i++ {
			req := httptest.NewRequest(http.MethodGet, "/auth/authorize", nil)
			ctx := metadata.WithClientMetadata(req.Context(), "192.168.1.1", "test-agent")
			req = req.WithContext(ctx)
			rr := httptest.NewRecorder()
			handler := middleware.RateLimit(models.ClassAuth)(next)
			handler.ServeHTTP(rr, req)
		}

		// After exceeding in-memory limit, should block
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

		middleware := New(limiter, s.logger, WithFallbackLimiter(s.fallback))

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
		for range 3 { // 3 successful probes threshold
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

// =============================================================================
// Global Throttle Tests
// =============================================================================
func (s *MiddlewareSecuritySuite) TestGlobalThrottle() {
	s.Run("global throttle allows request when under limit", func() {
		limiter := &mockRateLimiter{
			checkGlobalResult: true,
		}
		middleware := New(limiter, s.logger, WithFallbackLimiter(s.fallback))

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rr := httptest.NewRecorder()

		handler := middleware.GlobalThrottle()(next)
		handler.ServeHTTP(rr, req)

		s.True(nextCalled)
		s.Equal(http.StatusOK, rr.Code)
	})

	s.Run("global throttle blocks request with 503 payload", func() {
		limiter := &mockRateLimiter{
			checkGlobalResult: false,
		}
		middleware := New(limiter, s.logger, WithFallbackLimiter(s.fallback))

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rr := httptest.NewRecorder()

		handler := middleware.GlobalThrottle()(next)
		handler.ServeHTTP(rr, req)

		s.False(nextCalled)
		s.Equal(http.StatusServiceUnavailable, rr.Code)
		s.Equal("60", rr.Header().Get("Retry-After"))

		var payload models.ServiceOverloadedResponse
		err := json.Unmarshal(rr.Body.Bytes(), &payload)
		s.Require().NoError(err)
		s.Equal("service_unavailable", payload.Error)
	})
}

// =============================================================================
// Client Rate Limit Tests (PRD-017 FR-2c)
// =============================================================================
func (s *MiddlewareSecuritySuite) TestClientRateLimitMiddleware() {
	s.Run("missing client_id skips client rate limiting", func() {
		limiter := &mockClientLimiter{}
		middleware := NewClientMiddleware(limiter, s.logger, false)

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)
		rr := httptest.NewRecorder()

		handler := middleware.RateLimitClient()(next)
		handler.ServeHTTP(rr, req)

		s.True(nextCalled)
		s.Equal(http.StatusOK, rr.Code)
		s.Equal(0, limiter.called)
	})

	s.Run("reads client_id from query params", func() {
		limiter := &mockClientLimiter{
			result: &models.RateLimitResult{
				Allowed:   true,
				Limit:     10,
				Remaining: 9,
			},
		}
		middleware := NewClientMiddleware(limiter, s.logger, false)

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?client_id=client-123", nil)
		rr := httptest.NewRecorder()

		handler := middleware.RateLimitClient()(next)
		handler.ServeHTTP(rr, req)

		s.True(nextCalled)
		s.Equal(http.StatusOK, rr.Code)
		s.Equal("client-123", limiter.lastClientID)
		s.Equal("/oauth/authorize", limiter.lastEndpoint)
	})

	s.Run("reads client_id from form body for POST", func() {
		limiter := &mockClientLimiter{
			result: &models.RateLimitResult{
				Allowed:   true,
				Limit:     10,
				Remaining: 9,
			},
		}
		middleware := NewClientMiddleware(limiter, s.logger, false)

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("client_id=client-456"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		handler := middleware.RateLimitClient()(next)
		handler.ServeHTTP(rr, req)

		s.True(nextCalled)
		s.Equal(http.StatusOK, rr.Code)
		s.Equal("client-456", limiter.lastClientID)
		s.Equal("/oauth/token", limiter.lastEndpoint)
	})

	s.Run("blocked client returns 429 payload", func() {
		limiter := &mockClientLimiter{
			result: &models.RateLimitResult{
				Allowed:    false,
				Limit:      10,
				Remaining:  0,
				RetryAfter: 60,
			},
		}
		middleware := NewClientMiddleware(limiter, s.logger, false)

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?client_id=client-789", nil)
		rr := httptest.NewRecorder()

		handler := middleware.RateLimitClient()(next)
		handler.ServeHTTP(rr, req)

		s.Equal(http.StatusTooManyRequests, rr.Code)
		s.Equal("60", rr.Header().Get("Retry-After"))

		var payload models.ClientRateLimitExceededResponse
		err := json.Unmarshal(rr.Body.Bytes(), &payload)
		s.Require().NoError(err)
		s.Equal("client_rate_limit_exceeded", payload.Error)
	})

	s.Run("degraded header set when client circuit breaker opens", func() {
		limiter := &mockClientLimiter{
			checkErr: errors.New("client limiter unavailable"),
		}
		fallback := NewFallbackClientLimiter(&config.ClientLimitConfig{
			PublicLimit: config.Limit{RequestsPerWindow: 10, Window: time.Minute},
		})
		middleware := NewClientMiddleware(limiter, s.logger, false, WithClientFallbackLimiter(fallback))

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := middleware.RateLimitClient()(next)

		for i := range 5 {
			req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?client_id=client-999", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if i == 4 {
				s.Equal("degraded", rr.Header().Get("X-RateLimit-Status"))
			}
		}
	})
}
