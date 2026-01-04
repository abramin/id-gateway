package request

import (
	"log/slog"
	"mime"
	"net/http"
	"regexp"
	"runtime/debug"
	"time"

	"credo/pkg/platform/privacy"
	"credo/pkg/requestcontext"

	"github.com/google/uuid"
)

// MaxRequestIDLength is the maximum allowed length for X-Request-ID header
// to prevent header injection and log pollution attacks.
const MaxRequestIDLength = 128

// validRequestID matches alphanumeric characters, dashes, underscores, and periods.
// This prevents log injection and header manipulation attacks.
var validRequestID = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

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
						"request_id", requestcontext.RequestID(ctx),
					)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// RequestID adds a unique request ID to the context and response headers.
// If the client provides a valid X-Request-ID header, it will be used; otherwise a new UUID is generated.
// Client-provided IDs are validated: max 128 chars, alphanumeric/dash/underscore/period only.
// Invalid IDs are replaced with generated UUIDs to prevent log injection attacks.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if !isValidRequestID(requestID) {
			requestID = uuid.New().String()
		}

		ctx := requestcontext.WithRequestID(r.Context(), requestID)
		w.Header().Set("X-Request-ID", requestID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// isValidRequestID checks if a request ID is safe to use.
// Returns false for empty strings, oversized values, or values with invalid characters.
func isValidRequestID(id string) bool {
	if id == "" || len(id) > MaxRequestIDLength {
		return false
	}
	return validRequestID.MatchString(id)
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
			requestID := requestcontext.RequestID(ctx)

			// Skip noisy health checks unless they fail.
			if r.URL.Path == "/health" && wrapped.statusCode < http.StatusInternalServerError {
				return
			}

			logger.InfoContext(ctx, "http request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", wrapped.statusCode,
				"duration_ms", duration.Milliseconds(),
				"request_id", requestID,
				"remote_addr_prefix", privacy.AnonymizeIP(requestcontext.ClientIP(ctx)),
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
					_, _ = w.Write([]byte(`{"error":"invalid_content_type","error_description":"Content-Type must be application/json"}`)) //nolint:errcheck // headers already sent
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func LatencyMiddleware(m *Metrics) func(http.Handler) http.Handler {
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
