package httputil

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/middleware/auth"
)

func WriteJSON(w http.ResponseWriter, status int, response any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Errors after WriteHeader cannot change the status code, so we ignore encoding errors.
	// The response body may be incomplete, but headers are already sent.
	_ = json.NewEncoder(w).Encode(response)
}

// WriteError centralizes domain error translation to HTTP responses.
// It translates transport-agnostic domain errors into HTTP status codes and error responses.
func WriteError(w http.ResponseWriter, err error) {
	// Try domain error first
	var domainErr *dErrors.Error
	if errors.As(err, &domainErr) {
		status := DomainCodeToHTTPStatus(domainErr.Code)
		code := DomainCodeToHTTPCode(domainErr.Code)
		response := map[string]string{
			"error": code,
		}
		if domainErr.Message != "" {
			response["error_description"] = domainErr.Message
		}
		WriteJSON(w, status, response)
		return
	}

	// Fallback for unexpected errors
	WriteJSON(w, http.StatusInternalServerError, map[string]string{
		"error": DomainCodeToHTTPCode(dErrors.CodeInternal),
	})
}

// DomainCodeToHTTPStatus translates domain error codes to HTTP status codes.
func DomainCodeToHTTPStatus(code dErrors.Code) int {
	switch code {
	case dErrors.CodeNotFound:
		return http.StatusNotFound
	case dErrors.CodeBadRequest, dErrors.CodeValidation, dErrors.CodeInvalidInput, dErrors.CodeInvariantViolation:
		return http.StatusBadRequest
	case dErrors.CodeConflict:
		return http.StatusConflict
	case dErrors.CodeUnauthorized:
		return http.StatusUnauthorized
	case dErrors.CodeForbidden:
		return http.StatusForbidden
	case dErrors.CodeInvalidConsent, dErrors.CodeMissingConsent:
		return http.StatusForbidden
	case dErrors.CodePolicyViolation:
		return http.StatusPreconditionFailed
	case dErrors.CodeTimeout:
		return http.StatusGatewayTimeout
	case dErrors.CodeInternal:
		return http.StatusInternalServerError
	// OAuth 2.0 error codes (RFC 6749 §5.2) - all return 400 Bad Request
	case dErrors.CodeInvalidGrant, dErrors.CodeInvalidClient, dErrors.CodeUnsupportedGrantType, dErrors.CodeInvalidRequest, dErrors.CodeAccessDenied:
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

// RequireUserID extracts the authenticated user ID from context.
// Returns a domain error suitable for HTTP response on failure.
// This centralizes auth context extraction for handlers.
func RequireUserID(ctx context.Context, logger *slog.Logger, requestID string) (id.UserID, error) {
	userID := auth.GetUserID(ctx)
	if userID.IsNil() {
		if logger != nil {
			logger.ErrorContext(ctx, "userID missing from context despite auth middleware",
				"request_id", requestID)
		}
		return id.UserID{}, dErrors.New(dErrors.CodeInternal, "authentication context error")
	}
	return userID, nil
}

// DomainCodeToHTTPCode translates domain error codes to HTTP error codes (for JSON response).
func DomainCodeToHTTPCode(code dErrors.Code) string {
	switch code {
	case dErrors.CodeNotFound:
		return "not_found"
	case dErrors.CodeBadRequest, dErrors.CodeInvalidInput:
		return "bad_request"
	case dErrors.CodeValidation, dErrors.CodeInvariantViolation:
		return "validation_error"
	case dErrors.CodeConflict:
		return "conflict"
	case dErrors.CodeUnauthorized:
		return "unauthorized"
	case dErrors.CodeForbidden:
		return "forbidden"
	case dErrors.CodeInvalidConsent:
		return "invalid_consent"
	case dErrors.CodeMissingConsent:
		return "missing_consent"
	case dErrors.CodePolicyViolation:
		return "policy_violation"
	case dErrors.CodeTimeout:
		return "registry_timeout"
	case dErrors.CodeInternal:
		return "internal_error"
	// OAuth 2.0 error codes (RFC 6749 §5.2) - return standard OAuth error strings
	case dErrors.CodeInvalidGrant:
		return "invalid_grant"
	case dErrors.CodeInvalidClient:
		return "invalid_client"
	case dErrors.CodeUnsupportedGrantType:
		return "unsupported_grant_type"
	case dErrors.CodeInvalidRequest:
		return "invalid_request"
	case dErrors.CodeAccessDenied:
		return "access_denied"
	default:
		return "internal_error"
	}
}
