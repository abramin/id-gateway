// Package middleware provides HTTP middleware for rate limiting.
//
// This package wraps the rate limiting services as chi-compatible middleware,
// handling HTTP concerns (headers, response codes) and resilience (circuit breaker).
//
// Middleware types:
//   - RateLimit: Per-IP limiting for unauthenticated endpoints
//   - RateLimitAuthenticated: Combined IP+user limiting for protected endpoints
//   - GlobalThrottle: DDoS protection across all endpoints
//   - RateLimitClient: Per-OAuth-client limiting
//
// Resilience features:
//   - Circuit breaker with automatic fallback to in-memory store
//   - Fail-open by default (requests proceed on store errors)
//   - Configurable fail-closed mode for high-security deployments
//   - X-RateLimit-Status: degraded header when using fallback
//
// Standard response headers:
//   - X-RateLimit-Limit: Maximum requests allowed
//   - X-RateLimit-Remaining: Requests left in window
//   - X-RateLimit-Reset: Unix timestamp when window resets
//   - Retry-After: Seconds to wait (on 429 responses)
package middleware

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"credo/internal/ratelimit/models"
	"credo/pkg/platform/httputil"
	auth "credo/pkg/platform/middleware/auth"
	metadata "credo/pkg/platform/middleware/metadata"
	"credo/pkg/platform/privacy"
)

// RateLimiter is the interface consumed by the middleware.
// Implemented by the aggregated rate limit service that combines requestlimit and globalthrottle.
type RateLimiter interface {
	CheckIPRateLimit(ctx context.Context, ip string, class models.EndpointClass) (*models.RateLimitResult, error)
	CheckBothLimits(ctx context.Context, ip, userID string, class models.EndpointClass) (*models.RateLimitResult, error)
	CheckGlobalThrottle(ctx context.Context) (bool, error)
}

// ClientRateLimiter is the interface for per-OAuth-client rate limiting.
// Implemented by clientlimit.Service.
type ClientRateLimiter interface {
	Check(ctx context.Context, clientID, endpoint string) (*models.RateLimitResult, error)
}

// Middleware provides HTTP middleware for rate limiting with circuit breaker resilience.
type Middleware struct {
	limiter         RateLimiter
	logger          *slog.Logger
	disabled        bool
	failClosed      bool   // If true, reject requests when rate limiter is unavailable
	supportURL      string // URL for user support (included in auth lockout response)
	ipBreaker       *CircuitBreaker
	combinedBreaker *CircuitBreaker
	fallback        RateLimiter
}

// Option configures a Middleware instance.
type Option func(*Middleware)

// WithDisabled disables rate limiting entirely (for testing/development).
func WithDisabled(disabled bool) Option {
	return func(m *Middleware) {
		m.disabled = disabled
	}
}

// WithSupportURL sets the support URL included in lockout error responses.
func WithSupportURL(url string) Option {
	return func(m *Middleware) {
		m.supportURL = url
	}
}

// WithFallbackLimiter sets the fallback rate limiter used when the primary fails.
// Typically an in-memory implementation for resilience during store outages.
func WithFallbackLimiter(limiter RateLimiter) Option {
	return func(m *Middleware) {
		if limiter != nil {
			m.fallback = limiter
		}
	}
}

// WithFailClosed enables fail-closed behavior for high-security deployments.
// When enabled, requests are rejected (503) if the rate limiter is unavailable
// and no fallback succeeds. Default is fail-open (requests proceed on error).
func WithFailClosed(enabled bool) Option {
	return func(m *Middleware) {
		m.failClosed = enabled
	}
}

// New creates a rate limiting middleware with circuit breaker resilience.
func New(limiter RateLimiter, logger *slog.Logger, opts ...Option) *Middleware {
	m := &Middleware{
		limiter:         limiter,
		logger:          logger,
		ipBreaker:       newCircuitBreaker("ip"),
		combinedBreaker: newCircuitBreaker("combined"),
	}
	for _, opt := range opts {
		opt(m)
	}
	if m.disabled {
		logger.Info("rate limiting disabled")
	}
	return m
}

// RateLimit returns middleware that enforces per-IP rate limits.
// Use for unauthenticated endpoints. Returns 429 with Retry-After when exceeded.
func (m *Middleware) RateLimit(class models.EndpointClass) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if m.disabled {
				next.ServeHTTP(w, r)
				return
			}

			ctx := r.Context()
			ip := metadata.GetClientIP(ctx)

			result, degraded, err := m.checkIPRateLimit(ctx, ip, class)
			if err != nil && !degraded {
				// DESIGN DECISION: Fail-open on rate limit check errors.
				// This prioritizes availability over security - requests proceed when the
				// rate limit store is unavailable (e.g., Redis outage). The error is logged
				// for monitoring/alerting. This is a deliberate tradeoff: during store outages,
				// rate limiting is temporarily bypassed to avoid cascading failures.
				//
				// For high-security deployments requiring fail-closed behavior, see future
				// PRD for configurable FailClosed option.
				m.logger.Error("failed to check IP rate limit", "error", err, "ip_prefix", privacy.AnonymizeIP(ip))
				next.ServeHTTP(w, r)
				return
			}
			if err != nil && degraded {
				m.logger.Error("failed to check IP rate limit", "error", err, "ip_prefix", privacy.AnonymizeIP(ip))
			}

			//Add headers regardless of outcome
			if degraded {
				w.Header().Set("X-RateLimit-Status", "degraded")
			}
			addRateLimitHeaders(w, result)

			if !result.Allowed {
				writeRateLimitExceeded(w, result)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitAuthenticated returns middleware that enforces both IP and user rate limits.
// Use for authenticated endpoints. Applies the more restrictive of IP or user limits.
// Returns 429 with user-specific quota information when exceeded.
func (m *Middleware) RateLimitAuthenticated(class models.EndpointClass) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if m.disabled {
				next.ServeHTTP(w, r)
				return
			}

			ctx := r.Context()
			ip := metadata.GetClientIP(ctx)
			userID := auth.GetUserID(ctx).String()

			result, degraded, err := m.checkBothLimits(ctx, ip, userID, class)
			if err != nil && !degraded {
				// Fail-open: see RateLimit() for design rationale.
				m.logger.Error("failed to check combined rate limit", "error", err, "ip_prefix", privacy.AnonymizeIP(ip), "user_id", userID)
				next.ServeHTTP(w, r)
				return
			}
			if err != nil && degraded {
				m.logger.Error("failed to check combined rate limit", "error", err, "ip_prefix", privacy.AnonymizeIP(ip), "user_id", userID)
			}

			if degraded {
				w.Header().Set("X-RateLimit-Status", "degraded")
			}
			addRateLimitHeaders(w, result)

			if !result.Allowed {
				writeUserRateLimitExceeded(w, result)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GlobalThrottle returns middleware for global DDoS protection (PRD-017 FR-6).
// Limits total requests across all clients to protect against traffic floods.
// Returns 503 Service Unavailable when the global limit is exceeded.
func (m *Middleware) GlobalThrottle() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if m.disabled {
				next.ServeHTTP(w, r)
				return
			}

			ctx := r.Context()

			allowed, err := m.limiter.CheckGlobalThrottle(ctx)
			if err != nil {
				// Fail-open: see RateLimit() for design rationale.
				w.Header().Set("X-RateLimit-Status", "degraded")
				m.logger.Error("failed to check global throttle", "error", err)
				next.ServeHTTP(w, r)
				return
			}

			if !allowed {
				writeServiceOverloaded(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func addRateLimitHeaders(w http.ResponseWriter, result *models.RateLimitResult) {
	if result == nil {
		return
	}
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(result.ResetAt.Unix(), 10))
}

func writeRateLimitExceeded(w http.ResponseWriter, result *models.RateLimitResult) {
	w.Header().Set("Retry-After", strconv.Itoa(result.RetryAfter))
	httputil.WriteJSON(w, http.StatusTooManyRequests, &models.RateLimitExceededResponse{
		Error:      "rate_limit_exceeded",
		Message:    "Too many requests from this IP address. Please try again later.",
		RetryAfter: result.RetryAfter,
	})
}

func writeUserRateLimitExceeded(w http.ResponseWriter, result *models.RateLimitResult) {
	w.Header().Set("Retry-After", strconv.Itoa(result.RetryAfter))
	httputil.WriteJSON(w, http.StatusTooManyRequests, &models.UserRateLimitExceededResponse{
		Error:          "user_rate_limit_exceeded",
		Message:        "You have exceeded your request quota for this operation.",
		QuotaLimit:     result.Limit,
		QuotaRemaining: result.Remaining,
		QuotaReset:     result.ResetAt,
	})
}

func writeServiceOverloaded(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	httputil.WriteJSON(w, http.StatusServiceUnavailable, &models.ServiceOverloadedResponse{
		Error:      "service_unavailable",
		Message:    "Service is temporarily overloaded. Please try again later.",
		RetryAfter: 60,
	})
}

func writeClientRateLimitExceeded(w http.ResponseWriter, result *models.RateLimitResult) {
	w.Header().Set("Retry-After", strconv.Itoa(result.RetryAfter))
	httputil.WriteJSON(w, http.StatusTooManyRequests, &models.ClientRateLimitExceededResponse{
		Error:      "client_rate_limit_exceeded",
		Message:    "OAuth client has exceeded its request quota. Please retry later.",
		RetryAfter: result.RetryAfter,
	})
}

// errConflictingClientID indicates conflicting client_id values in different request locations.
var errConflictingClientID = errors.New("conflicting client_id values")

// extractClientID extracts client_id with strict ordering to prevent confusion attacks.
// Returns an error if both query and form body contain conflicting values.
func extractClientID(r *http.Request) (string, error) {
	queryClientID := r.URL.Query().Get("client_id")

	// For non-POST requests, only use query parameter
	if r.Method != http.MethodPost {
		return queryClientID, nil
	}

	// For POST requests, check form body (requires parsing)
	// Use PostFormValue to get ONLY form body values, not query params
	if err := r.ParseForm(); err != nil {
		// If form parsing fails, fall back to query-only
		return queryClientID, nil
	}

	formClientID := r.PostFormValue("client_id")

	// Both empty: no client_id
	if queryClientID == "" && formClientID == "" {
		return "", nil
	}

	// Only query has value
	if formClientID == "" {
		return queryClientID, nil
	}

	// Only form has value
	if queryClientID == "" {
		return formClientID, nil
	}

	// Both have values: must match
	if queryClientID != formClientID {
		return "", errConflictingClientID
	}

	// Both match: use query value (arbitrary choice, they're the same)
	return queryClientID, nil
}

// ClientMiddleware provides per-OAuth-client rate limiting (PRD-017 FR-2c).
// Applies different limits for confidential (server-side) vs public (SPA/mobile) clients.
type ClientMiddleware struct {
	limiter        ClientRateLimiter
	logger         *slog.Logger
	disabled       bool
	circuitBreaker *CircuitBreaker
	fallback       ClientRateLimiter
}

// ClientOption configures a ClientMiddleware instance.
type ClientOption func(*ClientMiddleware)

// WithClientFallbackLimiter sets the fallback for client rate limiting.
func WithClientFallbackLimiter(limiter ClientRateLimiter) ClientOption {
	return func(m *ClientMiddleware) {
		if limiter != nil {
			m.fallback = limiter
		}
	}
}

// NewClientMiddleware creates middleware for per-OAuth-client rate limiting.
func NewClientMiddleware(limiter ClientRateLimiter, logger *slog.Logger, disabled bool, opts ...ClientOption) *ClientMiddleware {
	m := &ClientMiddleware{
		limiter:        limiter,
		logger:         logger,
		disabled:       disabled,
		circuitBreaker: newCircuitBreaker("client"),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// RateLimitClient returns middleware that enforces per-client rate limits on OAuth endpoints.
// It extracts client_id from query parameters (for authorize) or request body (for token).
//
// # Client ID Extraction Order
//
// The extraction follows a strict order to prevent confusion attacks:
//  1. Query parameter (for authorize endpoint)
//  2. Form body (for token endpoint, POST only)
//
// If both sources provide conflicting values, the request is rejected to prevent
// bypass attacks where an attacker might send different client_ids in different locations.
func (m *ClientMiddleware) RateLimitClient() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if m.disabled {
				next.ServeHTTP(w, r)
				return
			}

			ctx := r.Context()

			// Extract client_id with strict ordering: query first, then form body for POST
			clientID, err := extractClientID(r)
			if err != nil {
				httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{
					"error":             "invalid_request",
					"error_description": "conflicting client_id values in request",
				})
				return
			}

			if clientID == "" {
				// No client_id, skip client rate limiting
				next.ServeHTTP(w, r)
				return
			}

			endpoint := r.URL.Path
			result, degraded, err := m.checkClientLimit(ctx, clientID, endpoint)
			if err != nil && !degraded {
				// Fail-open: see Middleware.RateLimit() for design rationale.
				m.logger.Error("failed to check client rate limit", "error", err)
				next.ServeHTTP(w, r)
				return
			}
			if err != nil && degraded {
				m.logger.Error("failed to check client rate limit", "error", err)
			}

			if degraded {
				w.Header().Set("X-RateLimit-Status", "degraded")
			}
			addRateLimitHeaders(w, result)

			if !result.Allowed {
				writeClientRateLimitExceeded(w, result)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func writeFailClosedError(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "30")
	httputil.WriteJSON(w, http.StatusServiceUnavailable, &models.ServiceOverloadedResponse{
		Error:      "rate_limit_unavailable",
		Message:    "Rate limiting service is temporarily unavailable. Please try again later.",
		RetryAfter: 30,
	})
}

// withCircuitBreaker wraps a rate limit check with circuit breaker logic.
// It handles primary check, fallback on failure, and circuit state transitions.
// Logs state transitions and fallback usage for observability.
func withCircuitBreaker[T any](
	breaker *CircuitBreaker,
	logger *slog.Logger,
	primary func() (T, error),
	fallback func() (T, error),
	fallbackName string,
) (result T, degraded bool, err error) {
	result, err = primary()
	if err != nil {
		return handlePrimaryFailure(breaker, logger, result, err, fallback, fallbackName)
	}
	return handlePrimarySuccess(breaker, logger, result, fallback, fallbackName)
}

// handlePrimaryFailure processes circuit breaker state after primary check fails.
func handlePrimaryFailure[T any](
	breaker *CircuitBreaker,
	logger *slog.Logger,
	result T,
	primaryErr error,
	fallback func() (T, error),
	fallbackName string,
) (T, bool, error) {
	useFallback, change := breaker.RecordFailure()
	logCircuitOpened(logger, breaker, change)

	if !useFallback || fallback == nil {
		return result, false, primaryErr
	}

	logFallbackUsage(logger, breaker, "circuit_open")
	return tryFallback(logger, result, primaryErr, fallback, fallbackName)
}

// handlePrimarySuccess processes circuit breaker state after primary check succeeds.
func handlePrimarySuccess[T any](
	breaker *CircuitBreaker,
	logger *slog.Logger,
	result T,
	fallback func() (T, error),
	fallbackName string,
) (T, bool, error) {
	usePrimary, change := breaker.RecordSuccess()
	logCircuitClosed(logger, breaker, change)

	if usePrimary || fallback == nil {
		return result, false, nil
	}

	logFallbackUsage(logger, breaker, "circuit_half_open")
	return tryFallback(logger, result, nil, fallback, fallbackName)
}

// tryFallback attempts the fallback function, returning primary result on fallback failure.
func tryFallback[T any](
	logger *slog.Logger,
	primaryResult T,
	primaryErr error,
	fallback func() (T, error),
	fallbackName string,
) (T, bool, error) {
	fallbackResult, fallbackErr := fallback()
	if fallbackErr != nil {
		if logger != nil {
			logger.Error("fallback "+fallbackName+" failed", "error", fallbackErr)
		}
		return primaryResult, false, primaryErr
	}
	return fallbackResult, true, primaryErr
}

func logCircuitOpened(logger *slog.Logger, breaker *CircuitBreaker, change StateChange) {
	if change.Opened && logger != nil {
		logger.Warn("circuit breaker opened",
			"breaker", breaker.Name(),
			"reason", "failure_threshold_reached",
		)
	}
}

func logCircuitClosed(logger *slog.Logger, breaker *CircuitBreaker, change StateChange) {
	if change.Closed && logger != nil {
		logger.Info("circuit breaker closed",
			"breaker", breaker.Name(),
			"reason", "recovery_complete",
		)
	}
}

func logFallbackUsage(logger *slog.Logger, breaker *CircuitBreaker, reason string) {
	if logger != nil {
		logger.Info("using fallback rate limiter",
			"breaker", breaker.Name(),
			"reason", reason,
		)
	}
}

func (m *Middleware) checkIPRateLimit(ctx context.Context, ip string, class models.EndpointClass) (*models.RateLimitResult, bool, error) {
	primary := func() (*models.RateLimitResult, error) {
		return m.limiter.CheckIPRateLimit(ctx, ip, class)
	}
	var fallback func() (*models.RateLimitResult, error)
	if m.fallback != nil {
		fallback = func() (*models.RateLimitResult, error) {
			return m.fallback.CheckIPRateLimit(ctx, ip, class)
		}
	}
	return withCircuitBreaker(m.ipBreaker, m.logger, primary, fallback, "IP rate limit")
}

func (m *Middleware) checkBothLimits(ctx context.Context, ip, userID string, class models.EndpointClass) (*models.RateLimitResult, bool, error) {
	primary := func() (*models.RateLimitResult, error) {
		return m.limiter.CheckBothLimits(ctx, ip, userID, class)
	}
	var fallback func() (*models.RateLimitResult, error)
	if m.fallback != nil {
		fallback = func() (*models.RateLimitResult, error) {
			return m.fallback.CheckBothLimits(ctx, ip, userID, class)
		}
	}
	return withCircuitBreaker(m.combinedBreaker, m.logger, primary, fallback, "combined rate limit")
}

func (m *ClientMiddleware) checkClientLimit(ctx context.Context, clientID, endpoint string) (*models.RateLimitResult, bool, error) {
	primary := func() (*models.RateLimitResult, error) {
		return m.limiter.Check(ctx, clientID, endpoint)
	}
	var fallback func() (*models.RateLimitResult, error)
	if m.fallback != nil {
		fallback = func() (*models.RateLimitResult, error) {
			return m.fallback.Check(ctx, clientID, endpoint)
		}
	}
	return withCircuitBreaker(m.circuitBreaker, m.logger, primary, fallback, "client rate limit")
}
