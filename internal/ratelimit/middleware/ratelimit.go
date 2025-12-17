package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	platformMW "credo/internal/platform/middleware"
	"credo/internal/ratelimit/models"
	"credo/internal/transport/httputil"
)

// RateLimiter defines the interface for rate limit checking.
// This is implemented by the ratelimit service.
type RateLimiter interface {
	// CheckIPRateLimit checks IP-based rate limit
	CheckIPRateLimit(ctx context.Context, ip string, class models.EndpointClass) (*models.RateLimitResult, error)

	// CheckUserRateLimit checks user-based rate limit
	CheckUserRateLimit(ctx context.Context, userID string, class models.EndpointClass) (*models.RateLimitResult, error)

	// CheckBothLimits checks both IP and user limits (both must pass)
	CheckBothLimits(ctx context.Context, ip, userID string, class models.EndpointClass) (*models.RateLimitResult, error)

	// CheckAuthRateLimit checks auth-specific limits with lockout
	CheckAuthRateLimit(ctx context.Context, identifier, ip string) (*models.RateLimitResult, error)

	// CheckGlobalThrottle checks global DDoS throttle
	CheckGlobalThrottle(ctx context.Context) (bool, error)
}

// Middleware provides HTTP middleware for rate limiting.
// Per PRD-017 TR-3: Middleware implementation.
type Middleware struct {
	limiter RateLimiter
	logger  *slog.Logger
}

// New creates a new rate limit Middleware.
func New(limiter RateLimiter, logger *slog.Logger) *Middleware {
	return &Middleware{
		limiter: limiter,
		logger:  logger,
	}
}

// RateLimit returns middleware that enforces per-IP rate limiting.
// Per PRD-017 FR-1, TR-3: Per-IP rate limiting middleware.
//
// TODO: Implement this middleware
// 1. Extract client IP from context (set by ClientMetadata middleware)
// 2. Check if allowlisted (via limiter)
// 3. Call limiter.CheckIPRateLimit
// 4. Add rate limit headers to response
// 5. If not allowed, return 429 with retry-after
// 6. Else call next handler
func (m *Middleware) RateLimit(class models.EndpointClass) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ip := platformMW.GetClientIP(ctx)

			// TODO: Implement rate limit check
			// result, err := m.limiter.CheckIPRateLimit(ctx, ip, class)
			// if err != nil { ... log and allow through ... }
			//
			// Add headers regardless of outcome
			// addRateLimitHeaders(w, result)
			//
			// if !result.Allowed {
			//     writeRateLimitExceeded(w, result)
			//     return
			// }

			_ = ip // Remove when implemented

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitAuthenticated returns middleware that enforces both IP and user rate limits.
// Per PRD-017 FR-2: Both limits must pass for authenticated endpoints.
//
// TODO: Implement this middleware
// 1. Extract client IP and user ID from context
// 2. Call limiter.CheckBothLimits
// 3. Add rate limit headers (use the more restrictive values)
// 4. If not allowed, return 429 with appropriate message
// 5. Else call next handler
func (m *Middleware) RateLimitAuthenticated(class models.EndpointClass) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ip := platformMW.GetClientIP(ctx)
			userID := platformMW.GetUserID(ctx)

			// TODO: Implement combined rate limit check
			// result, err := m.limiter.CheckBothLimits(ctx, ip, userID, class)
			// if err != nil { ... log and allow through ... }
			//
			// addRateLimitHeaders(w, result)
			//
			// if !result.Allowed {
			//     writeUserRateLimitExceeded(w, result)
			//     return
			// }

			_ = ip
			_ = userID

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitAuth returns middleware for authentication endpoints with lockout.
// Per PRD-017 FR-2b: OWASP authentication-specific protections.
//
// TODO: Implement this middleware
// This is applied to /auth/authorize, /auth/token, /auth/password-reset, /mfa/*
// 1. Extract client IP from context
// 2. Extract identifier (email/username) from request body if applicable
// 3. Call limiter.CheckAuthRateLimit
// 4. Apply progressive backoff delay if configured
// 5. If locked out, return 429 with lockout info
// 6. Else call next handler
func (m *Middleware) RateLimitAuth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ip := platformMW.GetClientIP(ctx)

			// TODO: Implement auth rate limit with lockout
			// Note: May need to peek at request body to get email/username
			// result, err := m.limiter.CheckAuthRateLimit(ctx, "", ip)
			// if err != nil { ... }
			//
			// addRateLimitHeaders(w, result)
			//
			// if !result.Allowed {
			//     writeAuthLockout(w, result)
			//     return
			// }

			_ = ip

			next.ServeHTTP(w, r)
		})
	}
}

// GlobalThrottle returns middleware for global DDoS protection.
// Per PRD-017 FR-6: Global request throttling.
//
// TODO: Implement this middleware
// 1. Call limiter.CheckGlobalThrottle
// 2. If throttled, return 503 Service Unavailable
// 3. Else call next handler
func (m *Middleware) GlobalThrottle() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// TODO: Implement global throttle
			// allowed, err := m.limiter.CheckGlobalThrottle(ctx)
			// if err != nil { ... log and allow through ... }
			//
			// if !allowed {
			//     writeServiceOverloaded(w)
			//     return
			// }

			_ = ctx

			next.ServeHTTP(w, r)
		})
	}
}

// addRateLimitHeaders adds X-RateLimit-* headers to the response.
// Per PRD-017 FR-1: Standard rate limit headers.
//
// TODO: Implement this helper
// Headers:
// - X-RateLimit-Limit: {limit}
// - X-RateLimit-Remaining: {remaining}
// - X-RateLimit-Reset: {unix timestamp}
func addRateLimitHeaders(w http.ResponseWriter, result *models.RateLimitResult) {
	if result == nil {
		return
	}
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(result.ResetAt.Unix(), 10))
}

// writeRateLimitExceeded writes a 429 response for IP rate limit exceeded.
// Per PRD-017 FR-1: 429 response format.
//
// TODO: Implement this helper
func writeRateLimitExceeded(w http.ResponseWriter, result *models.RateLimitResult) {
	w.Header().Set("Retry-After", strconv.Itoa(result.RetryAfter))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	httputil.WriteJSON(w, http.StatusTooManyRequests, &models.RateLimitExceededResponse{
		Error:      "rate_limit_exceeded",
		Message:    "Too many requests from this IP address. Please try again later.",
		RetryAfter: result.RetryAfter,
	})
}

// writeUserRateLimitExceeded writes a 429 response for user rate limit exceeded.
// Per PRD-017 FR-2: User-specific rate limit response.
//
// TODO: Implement this helper
func writeUserRateLimitExceeded(w http.ResponseWriter, result *models.RateLimitResult) {
	w.Header().Set("Retry-After", strconv.Itoa(result.RetryAfter))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	httputil.WriteJSON(w, http.StatusTooManyRequests, &models.UserRateLimitExceededResponse{
		Error:          "user_rate_limit_exceeded",
		Message:        "You have exceeded your request quota for this operation.",
		QuotaLimit:     result.Limit,
		QuotaRemaining: result.Remaining,
		QuotaReset:     result.ResetAt,
	})
}

// writeServiceOverloaded writes a 503 response for global throttle exceeded.
// Per PRD-017 FR-6: 503 response for DDoS protection.
//
// TODO: Implement this helper
func writeServiceOverloaded(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	httputil.WriteJSON(w, http.StatusServiceUnavailable, &models.ServiceOverloadedResponse{
		Error:      "service_unavailable",
		Message:    "Service is temporarily overloaded. Please try again later.",
		RetryAfter: 60,
	})
}

// Ensure unused imports are referenced
var _ = time.Now
