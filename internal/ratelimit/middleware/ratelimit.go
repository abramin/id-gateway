package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"credo/internal/ratelimit/models"
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
	limiter    RateLimiter
	logger     *slog.Logger
	disabled   bool
	supportURL string // URL for user support (included in auth lockout response)
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
	m := &Middleware{
		limiter: limiter,
		logger:  logger,
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

			result, err := m.limiter.CheckIPRateLimit(ctx, ip, class)
			if err != nil {
				m.logger.Error("failed to check IP rate limit", "error", err, "ip_prefix", privacy.AnonymizeIP(ip))
				next.ServeHTTP(w, r)
				return
			}

			//Add headers regardless of outcome
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

			result, err := m.limiter.CheckBothLimits(ctx, ip, userID, class)
			if err != nil {
				m.logger.Error("failed to check combined rate limit", "error", err, "ip_prefix", privacy.AnonymizeIP(ip), "user_id", userID)
				next.ServeHTTP(w, r)
				return
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
	limiter  ClientRateLimiter
	logger   *slog.Logger
	disabled bool
}

// NewClientMiddleware creates a new client rate limit middleware.
func NewClientMiddleware(limiter ClientRateLimiter, logger *slog.Logger, disabled bool) *ClientMiddleware {
	return &ClientMiddleware{
		limiter:  limiter,
		logger:   logger,
		disabled: disabled,
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
			result, err := m.limiter.Check(ctx, clientID, endpoint)
			if err != nil {
				m.logger.Error("failed to check client rate limit", "error", err)
				next.ServeHTTP(w, r)
				return
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

// Ensure unused imports are referenced
var _ = time.Now
