package middleware

import (
	"context"
	"log/slog"
	"mime"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"credo/internal/platform/metrics"

	"github.com/google/uuid"
)

// Recovery recovers from panics and returns a 500 error, preventing server crashes.
func Recovery(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					ctx := r.Context()
					logger.ErrorContext(ctx, "panic recovered",
						"error", err,
						"stack", string(debug.Stack()),
						"path", r.URL.Path,
						"method", r.Method,
						"request_id", GetRequestID(ctx),
					)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// RequestID adds a unique request ID to the context and response headers.
// If the client provides an X-Request-ID header, it will be used; otherwise a new UUID is generated.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		ctx := context.WithValue(r.Context(), requestIDKey{}, requestID)
		w.Header().Set("X-Request-ID", requestID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type requestIDKey struct{}

// GetRequestID retrieves the request ID from the context.
func GetRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey{}).(string); ok {
		return id
	}
	return ""
}

// Logger logs HTTP requests with method, path, status code, duration, and request ID.
func Logger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(wrapped, r)

			duration := time.Since(start)
			ctx := r.Context()
			requestID := GetRequestID(ctx)

			logger.InfoContext(ctx, "http request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", wrapped.statusCode,
				"duration_ms", duration.Milliseconds(),
				"request_id", requestID,
				"remote_addr", r.RemoteAddr,
			)
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Timeout wraps the handler with a timeout.
func Timeout(timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.TimeoutHandler(next, timeout, "Request Timeout")
	}
}

// ContentTypeJSON validates that POST/PUT/PATCH requests have Content-Type: application/json.
func ContentTypeJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			ct := r.Header.Get("Content-Type")
			if ct != "" {
				if mediaType, _, err := mime.ParseMediaType(ct); err != nil || mediaType != "application/json" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnsupportedMediaType)
					w.Write([]byte(`{"error":"invalid_content_type","error_description":"Content-Type must be application/json"}`))
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func LatencyMiddleware(m *metrics.Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			next.ServeHTTP(w, r)
			if m != nil {
				m.ObserveEndpointLatency(r.URL.Path, time.Since(start).Seconds())
			}
		})
	}
}

// Context keys for client metadata
type contextKeyClientIP struct{}
type contextKeyUserAgent struct{}
type contextKeyDeviceID struct{}
type contextKeyDeviceFingerprint struct{}

// ClientMetadata extracts client IP address and User-Agent from the request
// and adds them to the context for use by handlers and services.
// This middleware should be applied early in the chain.
func ClientMetadata(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		userAgent := r.Header.Get("User-Agent")

		ctx := r.Context()
		ctx = context.WithValue(ctx, contextKeyClientIP{}, ip)
		ctx = context.WithValue(ctx, contextKeyUserAgent{}, userAgent)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetClientIP retrieves the client IP address from the context.
func GetClientIP(ctx context.Context) string {
	if ip, ok := ctx.Value(contextKeyClientIP{}).(string); ok {
		return ip
	}
	return ""
}

// GetUserAgent retrieves the User-Agent from the context.
func GetUserAgent(ctx context.Context) string {
	if ua, ok := ctx.Value(contextKeyUserAgent{}).(string); ok {
		return ua
	}
	return ""
}

// GetDeviceID retrieves the device identifier (cookie value) from the context.
func GetDeviceID(ctx context.Context) string {
	if deviceID, ok := ctx.Value(contextKeyDeviceID{}).(string); ok {
		return deviceID
	}
	return ""
}

// WithClientMetadata injects client IP and User-Agent into a context.
// Useful for service unit tests that don't run the full HTTP middleware chain.
func WithClientMetadata(ctx context.Context, clientIP, userAgent string) context.Context {
	ctx = context.WithValue(ctx, contextKeyClientIP{}, clientIP)
	ctx = context.WithValue(ctx, contextKeyUserAgent{}, userAgent)
	return ctx
}

// WithDeviceID injects a device identifier into a context.
// Useful for service unit tests that don't run the full HTTP middleware chain.
func WithDeviceID(ctx context.Context, deviceID string) context.Context {
	return context.WithValue(ctx, contextKeyDeviceID{}, deviceID)
}

// GetDeviceFingerprint retrieves the pre-computed device fingerprint from the context.
func GetDeviceFingerprint(ctx context.Context) string {
	if fp, ok := ctx.Value(contextKeyDeviceFingerprint{}).(string); ok {
		return fp
	}
	return ""
}

// WithDeviceFingerprint injects a device fingerprint into a context.
// Useful for service unit tests that don't run the full HTTP middleware chain.
func WithDeviceFingerprint(ctx context.Context, fingerprint string) context.Context {
	return context.WithValue(ctx, contextKeyDeviceFingerprint{}, fingerprint)
}

// getClientIP extracts the real client IP from the request, handling proxies and load balancers.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (standard for proxied requests)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs (client, proxy1, proxy2, ...)
		// Take the first IP which is the original client
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header (used by nginx and other proxies)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr (direct connection)
	// RemoteAddr is in format "ip:port", so we need to strip the port
	if addr := r.RemoteAddr; addr != "" {
		// For IPv6, format is [::1]:port
		// For IPv4, format is 127.0.0.1:port
		if idx := strings.LastIndex(addr, ":"); idx != -1 {
			return addr[:idx]
		}
		return addr
	}

	return "unknown"
}
