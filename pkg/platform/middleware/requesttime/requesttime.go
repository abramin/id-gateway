// Package requesttime provides middleware for request-scoped time.
// All operations within a single HTTP request use the same "now" timestamp,
// ensuring consistency in audit logs, domain timestamps, and time-sensitive operations.
package requesttime

import (
	"net/http"
	"time"

	"credo/pkg/requestcontext"
)

// Middleware captures the current time at the start of the request
// and stores it in the context for consistent time references throughout the request.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		ctx := requestcontext.WithTime(r.Context(), now)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
