package middleware

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
)

// JWTValidator defines the interface for validating JWT tokens
type JWTValidator interface {
	ValidateToken(tokenString string) (*JWTClaims, error)
}

// JWTClaims represents the claims we expect from the JWT validator
type JWTClaims struct {
	UserID    string
	SessionID string
	ClientID  string
}

// Context keys for storing authenticated user information
type contextKeyUserID struct{}
type contextKeySessionID struct{}
type contextKeyClientID struct{}

// ContextKeyUserID is exported for use in handlers
const ContextKeyUserID = contextKeyUserID{}

// GetUserID retrieves the authenticated user ID from the context
// TODO: Implement this function
// - Extract the user ID from context using ContextKeyUserID
// - Type assert to string
// - Return empty string if not found or wrong type
func GetUserID(ctx context.Context) string {
	// TODO: Your implementation here
	panic("not implemented")
}

// GetSessionID retrieves the session ID from the context
// TODO: Implement this function
// - Extract the session ID from context using contextKeySessionID
// - Type assert to string
// - Return empty string if not found
func GetSessionID(ctx context.Context) string {
	// TODO: Your implementation here
	panic("not implemented")
}

// GetClientID retrieves the client ID from the context
// TODO: Implement this function
// - Extract the client ID from context using contextKeyClientID
// - Type assert to string
// - Return empty string if not found
func GetClientID(ctx context.Context) string {
	// TODO: Your implementation here
	panic("not implemented")
}

// RequireAuth is middleware that validates JWT tokens and populates context
// TODO: Implement this middleware
// Steps:
// 1. Extract the Authorization header from the request
// 2. Check if it starts with "Bearer "
// 3. Extract the token (everything after "Bearer ")
// 4. Call validator.ValidateToken(token)
// 5. If validation fails:
//    - Log a warning with the error and request ID
//    - Return 401 Unauthorized with JSON error
// 6. If validation succeeds:
//    - Add UserID, SessionID, and ClientID to context using context.WithValue
//    - Call next.ServeHTTP with the updated context
//
// Error response format: {"error":"unauthorized","error_description":"Invalid or expired token"}
func RequireAuth(validator JWTValidator, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// TODO: Your implementation here
			// Hint: Use r.Header.Get("Authorization")
			// Hint: Use strings.HasPrefix and strings.TrimPrefix
			// Hint: Create new context with multiple WithValue calls
			// Hint: Use r.WithContext(ctx) to pass updated context
			panic("not implemented")
		})
	}
}

// OptionalAuth is middleware that validates JWT if present, but allows unauthenticated requests
// TODO: Implement this middleware (bonus/optional)
// Same as RequireAuth, but if no Authorization header is present or validation fails,
// still call next.ServeHTTP (without setting context values)
// This is useful for endpoints that have different behavior for authenticated vs anonymous users
func OptionalAuth(validator JWTValidator, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// TODO: Your implementation here (optional)
			// This is a bonus exercise - implement if you want extra practice
			next.ServeHTTP(w, r)
		})
	}
}
