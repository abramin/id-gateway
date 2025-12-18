package middleware

import (
	"log/slog"
	"net/http"
)

func RequireAdminToken(expectedToken string, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("X-Admin-Token")
			if token != expectedToken {
				ctx := r.Context()
				requestID := GetRequestID(ctx)
				logger.WarnContext(ctx, "admin token mismatch",
					"request_id", requestID,
				)
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"unauthorized","error_description":"admin token required"}`))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
