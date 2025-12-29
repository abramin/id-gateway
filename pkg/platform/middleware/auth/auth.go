package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	id "credo/pkg/domain"
	"credo/pkg/requestcontext"
)

// JWTValidator defines the interface for validating JWT tokens
type JWTValidator interface {
	ValidateToken(tokenString string) (*JWTClaims, error)
}

// TokenRevocationChecker defines the interface for checking if tokens are revoked
type TokenRevocationChecker interface {
	IsTokenRevoked(ctx context.Context, jti string) (bool, error)
}

// JWTClaims represents the claims we expect from the JWT validator
type JWTClaims struct {
	UserID    string
	SessionID string
	ClientID  string
	JTI       string // JWT ID for revocation tracking
}

// writeJSONError writes a JSON error response with the given status code and error details.
func writeJSONError(w http.ResponseWriter, status int, errCode, errDesc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(fmt.Appendf(nil, `{"error":"%s","error_description":"%s"}`, errCode, errDesc))
}

// revocationResult represents the outcome of a token revocation check.
type revocationResult int

const (
	revocationOK         revocationResult = iota // Token is valid, not revoked
	revocationMissingJTI                         // Token missing required JTI claim
	revocationRevoked                            // Token has been revoked
	revocationError                              // Error checking revocation status
)

// checkRevocation verifies that a token has not been revoked.
// Returns revocationOK if the token is valid, or an appropriate error state.
func checkRevocation(ctx context.Context, checker TokenRevocationChecker, jti string, logger *slog.Logger) revocationResult {
	if checker == nil {
		return revocationOK
	}

	if jti == "" {
		requestID := requestcontext.RequestID(ctx)
		logger.WarnContext(ctx, "unauthorized access - missing token jti",
			"request_id", requestID,
		)
		return revocationMissingJTI
	}

	revoked, err := checker.IsTokenRevoked(ctx, jti)
	if err != nil {
		requestID := requestcontext.RequestID(ctx)
		logger.ErrorContext(ctx, "failed to check token revocation",
			"error", err,
			"request_id", requestID,
		)
		return revocationError
	}

	if revoked {
		requestID := requestcontext.RequestID(ctx)
		logger.WarnContext(ctx, "unauthorized access - token revoked",
			"jti", jti,
			"request_id", requestID,
		)
		return revocationRevoked
	}

	return revocationOK
}

// parsedClaims holds the typed IDs parsed from JWT claims.
type parsedClaims struct {
	UserID    id.UserID
	SessionID id.SessionID
	ClientID  id.ClientID
}

// parseClaims converts string IDs from JWT claims to typed IDs.
// Returns an error if any ID has an invalid format.
func parseClaims(claims *JWTClaims) (*parsedClaims, error) {
	userID, err := id.ParseUserID(claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user_id: %w", err)
	}

	sessionID, err := id.ParseSessionID(claims.SessionID)
	if err != nil {
		return nil, fmt.Errorf("invalid session_id: %w", err)
	}

	// ClientID may be empty for some token types, so only parse if present
	var clientID id.ClientID
	if claims.ClientID != "" {
		clientID, err = id.ParseClientID(claims.ClientID)
		if err != nil {
			return nil, fmt.Errorf("invalid client_id: %w", err)
		}
	}

	return &parsedClaims{
		UserID:    userID,
		SessionID: sessionID,
		ClientID:  clientID,
	}, nil
}

// RequireAuth returns middleware that validates JWT tokens and populates context with typed IDs.
// It validates the token, checks revocation status, parses claim IDs, and stores typed IDs in context.
func RequireAuth(validator JWTValidator, revocationChecker TokenRevocationChecker, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			authHeader := r.Header.Get("Authorization")

			token, ok := strings.CutPrefix(authHeader, "Bearer ")
			if !ok {
				requestID := requestcontext.RequestID(ctx)
				logger.WarnContext(ctx, "unauthorized access - missing token",
					"request_id", requestID,
				)
				writeJSONError(w, http.StatusUnauthorized, "unauthorized", "Missing or invalid Authorization header")
				return
			}

			claims, err := validator.ValidateToken(token)
			if err != nil {
				requestID := requestcontext.RequestID(ctx)
				logger.WarnContext(ctx, "unauthorized access - invalid token",
					"error", err,
					"request_id", requestID,
				)
				writeJSONError(w, http.StatusUnauthorized, "unauthorized", "Invalid or expired token")
				return
			}

			// TR-4: Middleware revocation check (PRD-016).
			switch checkRevocation(ctx, revocationChecker, claims.JTI, logger) {
			case revocationMissingJTI, revocationRevoked:
				writeJSONError(w, http.StatusUnauthorized, "unauthorized", "Token has been revoked")
				return
			case revocationError:
				writeJSONError(w, http.StatusInternalServerError, "internal_error", "Failed to validate token")
				return
			}

			// Parse string IDs to typed IDs
			parsed, err := parseClaims(claims)
			if err != nil {
				requestID := requestcontext.RequestID(ctx)
				logger.WarnContext(ctx, "unauthorized access - malformed token claims",
					"error", err,
					"request_id", requestID,
				)
				writeJSONError(w, http.StatusUnauthorized, "unauthorized", "Invalid or expired token")
				return
			}

			// Store typed IDs in context
			ctx = requestcontext.WithUserID(ctx, parsed.UserID)
			ctx = requestcontext.WithSessionID(ctx, parsed.SessionID)
			ctx = requestcontext.WithClientID(ctx, parsed.ClientID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
