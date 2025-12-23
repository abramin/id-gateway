// Package requesttime provides middleware and utilities for request-scoped time.
// All operations within a single HTTP request use the same "now" timestamp,
// ensuring consistency in audit logs, domain timestamps, and time-sensitive operations.
package requesttime

import (
	"context"
	"net/http"
	"time"
)

type contextKeyRequestTime struct{}

// Middleware captures the current time at the start of the request
// and stores it in the context for consistent time references throughout the request.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		ctx := context.WithValue(r.Context(), contextKeyRequestTime{}, now)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Now retrieves the request-scoped time from context.
// Falls back to time.Now() if not set (for non-HTTP contexts like workers, CLI, tests).
func Now(ctx context.Context) time.Time {
	if t, ok := ctx.Value(contextKeyRequestTime{}).(time.Time); ok {
		return t
	}
	return time.Now()
}

// WithTime injects a specific time into a context.
// Useful for:
//   - Service unit tests that don't run the full HTTP middleware chain
//   - Workers that need consistent time within a batch operation
//   - CLI commands
func WithTime(ctx context.Context, t time.Time) context.Context {
	return context.WithValue(ctx, contextKeyRequestTime{}, t)
}
