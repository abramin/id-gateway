package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"sync"

	"credo/internal/ratelimit/config"
	"credo/internal/ratelimit/models"
	"credo/internal/ratelimit/service/requestlimit"
	"credo/internal/ratelimit/store/allowlist"
	"credo/internal/ratelimit/store/bucket"
	"credo/pkg/platform/httputil"
	auth "credo/pkg/platform/middleware/auth"
	metadata "credo/pkg/platform/middleware/metadata"
	"credo/pkg/platform/privacy"
)

type RateLimiter interface {
	CheckIPRateLimit(ctx context.Context, ip string, class models.EndpointClass) (*models.RateLimitResult, error)
	CheckUserRateLimit(ctx context.Context, userID string, class models.EndpointClass) (*models.RateLimitResult, error)
	CheckBothLimits(ctx context.Context, ip, userID string, class models.EndpointClass) (*models.RateLimitResult, error)
	CheckAuthRateLimit(ctx context.Context, identifier, ip string) (*models.AuthRateLimitResult, error)
	CheckGlobalThrottle(ctx context.Context) (bool, error)
}

type ClientRateLimiter interface {
	Check(ctx context.Context, clientID, endpoint string) (*models.RateLimitResult, error)
}

type Middleware struct {
	limiter        RateLimiter
	logger         *slog.Logger
	disabled       bool
	supportURL     string // URL for user support (included in auth lockout response)
	circuitBreaker *CircuitBreaker
	fallback       *fallbackLimiter
}

// Circuit breaker state (PRD-017 FR-7):
// - Track consecutive limiter errors.
// - Open circuit after N failures; during open, use in-memory fallback.
// - When open, set X-RateLimit-Status: degraded so callers know they’re in fallback mode.
// - Close circuit after M consecutive successful primary checks.
type CircuitBreaker struct {
	mu               sync.Mutex
	state            circuitState
	failureCount     int
	successCount     int
	failureThreshold int
	successThreshold int
}

type circuitState int

const (
	circuitClosed circuitState = iota
	circuitOpen
)

func newCircuitBreaker() *CircuitBreaker {
	return &CircuitBreaker{
		state:            circuitClosed,
		failureThreshold: 5,
		successThreshold: 3,
	}
}

func (c *CircuitBreaker) IsOpen() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state == circuitOpen
}

func (c *CircuitBreaker) RecordFailure() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failureCount++
	c.successCount = 0
	if c.state == circuitOpen {
		return true
	}
	if c.failureCount >= c.failureThreshold {
		c.state = circuitOpen
		return true
	}
	return false
}

func (c *CircuitBreaker) RecordSuccess() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == circuitOpen {
		c.successCount++
		if c.successCount >= c.successThreshold {
			c.state = circuitClosed
			c.failureCount = 0
			c.successCount = 0
			return true
		}
		return false
	}
	c.failureCount = 0
	return true
}

type fallbackLimiter struct {
	requests *requestlimit.Service
}

func newFallbackLimiter(logger *slog.Logger) *fallbackLimiter {
	requests, err := requestlimit.New(
		bucket.New(),
		allowlist.New(),
		requestlimit.WithLogger(logger),
	)
	if err != nil {
		if logger != nil {
			logger.Error("failed to initialize fallback rate limiter", "error", err)
		}
		return nil
	}
	return &fallbackLimiter{requests: requests}
}

func (f *fallbackLimiter) CheckIPRateLimit(ctx context.Context, ip string, class models.EndpointClass) (*models.RateLimitResult, error) {
	return f.requests.CheckIP(ctx, ip, class)
}

func (f *fallbackLimiter) CheckUserRateLimit(ctx context.Context, userID string, class models.EndpointClass) (*models.RateLimitResult, error) {
	return f.requests.CheckUser(ctx, userID, class)
}

func (f *fallbackLimiter) CheckBothLimits(ctx context.Context, ip, userID string, class models.EndpointClass) (*models.RateLimitResult, error) {
	return f.requests.CheckBoth(ctx, ip, userID, class)
}

func (f *fallbackLimiter) CheckAuthRateLimit(ctx context.Context, identifier, ip string) (*models.AuthRateLimitResult, error) {
	result, err := f.requests.CheckIP(ctx, ip, models.ClassAuth)
	if err != nil {
		return nil, err
	}
	return &models.AuthRateLimitResult{
		RateLimitResult: *result,
		RequiresCaptcha: false,
		FailureCount:    0,
	}, nil
}

func (f *fallbackLimiter) CheckGlobalThrottle(ctx context.Context) (bool, error) {
	return true, nil
}

type Option func(*Middleware)

func WithDisabled(disabled bool) Option {
	return func(m *Middleware) {
		m.disabled = disabled
	}
}

func WithSupportURL(url string) Option {
	return func(m *Middleware) {
		m.supportURL = url
	}
}

func New(limiter RateLimiter, logger *slog.Logger, opts ...Option) *Middleware {
	fallback := newFallbackLimiter(logger)
	m := &Middleware{
		limiter:        limiter,
		logger:         logger,
		circuitBreaker: newCircuitBreaker(),
		fallback:       fallback,
	}
	for _, opt := range opts {
		opt(m)
	}
	if m.disabled {
		logger.Info("rate limiting disabled")
	}
	return m
}

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

func (m *Middleware) RateLimitAuthenticated(class models.EndpointClass) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if m.disabled {
				next.ServeHTTP(w, r)
				return
			}

			ctx := r.Context()
			ip := metadata.GetClientIP(ctx)
			userID := auth.GetUserID(ctx)

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

// GlobalThrottle returns middleware for global DDoS protection.
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

type ClientMiddleware struct {
	limiter        ClientRateLimiter
	logger         *slog.Logger
	disabled       bool
	circuitBreaker *CircuitBreaker
	fallback       *fallbackClientLimiter
}

// NewClientMiddleware creates a new client rate limit middleware.
func NewClientMiddleware(limiter ClientRateLimiter, logger *slog.Logger, disabled bool) *ClientMiddleware {
	return &ClientMiddleware{
		limiter:        limiter,
		logger:         logger,
		disabled:       disabled,
		circuitBreaker: newCircuitBreaker(),
		fallback:       newFallbackClientLimiter(),
	}
}

// RateLimitClient returns middleware that enforces per-client rate limits on OAuth endpoints.
// It extracts client_id from query parameters (for authorize) or request body (for token).
func (m *ClientMiddleware) RateLimitClient() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if m.disabled {
				next.ServeHTTP(w, r)
				return
			}

			ctx := r.Context()

			// Extract client_id from query params (authorize) or form data (token)
			clientID := r.URL.Query().Get("client_id")
			if clientID == "" {
				// Try form data for POST requests
				if r.Method == http.MethodPost {
					clientID = r.FormValue("client_id")
				}
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

func (m *Middleware) checkIPRateLimit(ctx context.Context, ip string, class models.EndpointClass) (*models.RateLimitResult, bool, error) {
	result, err := m.limiter.CheckIPRateLimit(ctx, ip, class)
	if err != nil {
		if m.circuitBreaker.RecordFailure() && m.fallback != nil {
			fallbackResult, fallbackErr := m.fallback.CheckIPRateLimit(ctx, ip, class)
			if fallbackErr != nil {
				if m.logger != nil {
					m.logger.Error("fallback IP rate limit failed", "error", fallbackErr)
				}
				return nil, false, err
			}
			return fallbackResult, true, err
		}
		return nil, false, err
	}

	if !m.circuitBreaker.RecordSuccess() && m.fallback != nil {
		fallbackResult, fallbackErr := m.fallback.CheckIPRateLimit(ctx, ip, class)
		if fallbackErr != nil {
			if m.logger != nil {
				m.logger.Error("fallback IP rate limit failed", "error", fallbackErr)
			}
			return result, false, nil
		}
		return fallbackResult, true, nil
	}

	return result, false, nil
}

func (m *Middleware) checkBothLimits(ctx context.Context, ip, userID string, class models.EndpointClass) (*models.RateLimitResult, bool, error) {
	result, err := m.limiter.CheckBothLimits(ctx, ip, userID, class)
	if err != nil {
		if m.circuitBreaker.RecordFailure() && m.fallback != nil {
			fallbackResult, fallbackErr := m.fallback.CheckBothLimits(ctx, ip, userID, class)
			if fallbackErr != nil {
				if m.logger != nil {
					m.logger.Error("fallback combined rate limit failed", "error", fallbackErr)
				}
				return nil, false, err
			}
			return fallbackResult, true, err
		}
		return nil, false, err
	}

	if !m.circuitBreaker.RecordSuccess() && m.fallback != nil {
		fallbackResult, fallbackErr := m.fallback.CheckBothLimits(ctx, ip, userID, class)
		if fallbackErr != nil {
			if m.logger != nil {
				m.logger.Error("fallback combined rate limit failed", "error", fallbackErr)
			}
			return result, false, nil
		}
		return fallbackResult, true, nil
	}

	return result, false, nil
}

type fallbackClientLimiter struct {
	buckets *bucket.InMemoryBucketStore
	limit   config.Limit
}

func newFallbackClientLimiter() *fallbackClientLimiter {
	limit := config.DefaultConfig().ClientLimits.PublicLimit
	return &fallbackClientLimiter{
		buckets: bucket.New(),
		limit:   limit,
	}
}

func (f *fallbackClientLimiter) Check(ctx context.Context, clientID, endpoint string) (*models.RateLimitResult, error) {
	key := "client:" + models.SanitizeKeySegment(clientID) + ":" + models.SanitizeKeySegment(endpoint)
	return f.buckets.Allow(ctx, key, f.limit.RequestsPerWindow, f.limit.Window)
}

func (m *ClientMiddleware) checkClientLimit(ctx context.Context, clientID, endpoint string) (*models.RateLimitResult, bool, error) {
	result, err := m.limiter.Check(ctx, clientID, endpoint)
	if err != nil {
		if m.circuitBreaker.RecordFailure() && m.fallback != nil {
			fallbackResult, fallbackErr := m.fallback.Check(ctx, clientID, endpoint)
			if fallbackErr != nil {
				if m.logger != nil {
					m.logger.Error("fallback client rate limit failed", "error", fallbackErr)
				}
				return nil, false, err
			}
			return fallbackResult, true, err
		}
		return nil, false, err
	}

	if !m.circuitBreaker.RecordSuccess() && m.fallback != nil {
		fallbackResult, fallbackErr := m.fallback.Check(ctx, clientID, endpoint)
		if fallbackErr != nil {
			if m.logger != nil {
				m.logger.Error("fallback client rate limit failed", "error", fallbackErr)
			}
			return result, false, nil
		}
		return fallbackResult, true, nil
	}

	return result, false, nil
}
