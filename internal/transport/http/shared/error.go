package shared

import (
	"errors"
	"net/http"

	"credo/internal/transport/http/shared/json"
	dErrors "credo/pkg/domain-errors"
)

// WriteError centralizes domain error translation to HTTP responses.
// It translates transport-agnostic domain errors into HTTP status codes and error responses.
func WriteError(w http.ResponseWriter, err error) {
	// Try domain error first (new approach)
	var domainErr dErrors.DomainError
	if errors.As(err, &domainErr) {
		status := DomainCodeToHTTPStatus(domainErr.Code)
		code := DomainCodeToHTTPCode(domainErr.Code)
		response := map[string]string{
			"error": code,
		}
		if domainErr.Message != "" {
			response["error_description"] = domainErr.Message
		}
		json.WriteJSON(w, status, response)
		return
	}

	// Fallback for unexpected errors
	json.WriteJSON(w, http.StatusInternalServerError, map[string]string{
		"error": DomainCodeToHTTPCode(dErrors.CodeInternal),
	})
}

// DomainCodeToHTTPStatus translates domain error codes to HTTP status codes.
func DomainCodeToHTTPStatus(code dErrors.Code) int {
	switch code {
	case dErrors.CodeNotFound:
		return http.StatusNotFound
	case dErrors.CodeBadRequest, dErrors.CodeValidation, dErrors.CodeInvalidInput:
		return http.StatusBadRequest
	case dErrors.CodeConflict:
		return http.StatusConflict
	case dErrors.CodeUnauthorized:
		return http.StatusUnauthorized
	case dErrors.CodeInvalidConsent, dErrors.CodeMissingConsent:
		return http.StatusForbidden
	case dErrors.CodePolicyViolation:
		return http.StatusPreconditionFailed
	case dErrors.CodeTimeout:
		return http.StatusGatewayTimeout
	case dErrors.CodeInternal:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

// DomainCodeToHTTPCode translates domain error codes to HTTP error codes (for JSON response).
func DomainCodeToHTTPCode(code dErrors.Code) string {
	switch code {
	case dErrors.CodeNotFound:
		return "not_found"
	case dErrors.CodeBadRequest:
		return "bad_request"
	case dErrors.CodeValidation:
		return "bad_request"
	case dErrors.CodeInvalidInput:
		return "bad_request"
	case dErrors.CodeConflict:
		return "conflict"
	case dErrors.CodeUnauthorized:
		return "unauthorized"
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
	default:
		return "internal_error"
	}
}
