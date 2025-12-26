package request

import (
	"net/http"
)

// BodyLimit returns middleware that limits the size of request bodies.
// Uses http.MaxBytesReader which:
// - Returns 413 Request Entity Too Large on overflow
// - Closes the connection to prevent slow-loris attacks
// - Should be applied early in the middleware chain (before JSON parsing)
func BodyLimit(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}
