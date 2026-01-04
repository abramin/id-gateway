package admin

import (
	"context"
	"credo/pkg/requestcontext"
	"crypto/subtle"
	"log/slog"
	"net/http"
)

// Context key for storing admin actor identifier.
type contextKeyAdminActorID struct{}

// ContextKeyAdminActorID is exported for use in handlers and tests.
var ContextKeyAdminActorID = contextKeyAdminActorID{}

type contextKeyAdminAuthorized struct{}

var adminAuthorizedContextKey = contextKeyAdminAuthorized{}

// GetAdminActorID retrieves the admin actor identifier from the context.
// Returns empty string if not set or if this is not an admin request.
func GetAdminActorID(ctx context.Context) string {
	if actorID, ok := ctx.Value(ContextKeyAdminActorID).(string); ok {
		return actorID
	}
	return ""
}

// IsAdminRequest reports whether the admin token middleware authenticated this request.
func IsAdminRequest(ctx context.Context) bool {
	authorized, ok := ctx.Value(adminAuthorizedContextKey).(bool)
	return ok && authorized
}

func RequireAdminToken(expectedToken string, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("X-Admin-Token")
			// Use constant-time comparison to prevent timing attacks
			if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
				ctx := r.Context()
				requestID := requestcontext.RequestID(ctx)
				logger.WarnContext(ctx, "admin token mismatch",
					"request_id", requestID,
				)
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"unauthorized","error_description":"admin token required"}`)) //nolint:errcheck // headers already sent
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, adminAuthorizedContextKey, true)
			// Capture admin actor identifier for audit attribution.
			// This header identifies which admin performed the action.
			if actorID := r.Header.Get("X-Admin-Actor-ID"); actorID != "" {
				ctx = context.WithValue(ctx, ContextKeyAdminActorID, actorID)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
