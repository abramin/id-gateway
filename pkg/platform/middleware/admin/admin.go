package admin

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/http"

	request "credo/pkg/platform/middleware/request"
)

// Context key for storing admin actor identifier.
type contextKeyAdminActorID struct{}

// ContextKeyAdminActorID is exported for use in handlers and tests.
var ContextKeyAdminActorID = contextKeyAdminActorID{}

// GetAdminActorID retrieves the admin actor identifier from the context.
// Returns empty string if not set or if this is not an admin request.
func GetAdminActorID(ctx context.Context) string {
	if actorID, ok := ctx.Value(ContextKeyAdminActorID).(string); ok {
		return actorID
	}
	return ""
}

func RequireAdminToken(expectedToken string, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("X-Admin-Token")
			// Use constant-time comparison to prevent timing attacks
			if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
				ctx := r.Context()
				requestID := request.GetRequestID(ctx)
				logger.WarnContext(ctx, "admin token mismatch",
					"request_id", requestID,
				)
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"unauthorized","error_description":"admin token required"}`))
				return
			}

			ctx := r.Context()
			// Capture admin actor identifier for audit attribution.
			// This header identifies which admin performed the action.
			if actorID := r.Header.Get("X-Admin-Actor-ID"); actorID != "" {
				ctx = context.WithValue(ctx, ContextKeyAdminActorID, actorID)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
