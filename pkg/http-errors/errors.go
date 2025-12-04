package httpErrors

import "net/http"

// Code enumerates typed error categories so the HTTP layer can map them cleanly.
type Code string

const (
	CodeInvalidInput    Code = "invalid_input"
	CodeInvalidRequest  Code = "invalid_request"
	CodeUnauthorized    Code = "unauthorized"
	CodeNotFound        Code = "not_found"
	CodeConflict        Code = "conflict"
	CodeInternal        Code = "internal_error"
	CodeInvalidConsent  Code = "invalid_consent"
	CodeMissingConsent  Code = "missing_consent"
	CodePolicyViolation Code = "policy_violation"
	CodeRegistryTimeout Code = "registry_timeout"
)

// GatewayError wraps domain or infrastructure failures with a stable code.
type GatewayError struct {
	Code    Code
	Message string
	Err     error
}

func (e GatewayError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return string(e.Code)
}

func (e GatewayError) Unwrap() error {
	return e.Err
}

func New(code Code, msg string) GatewayError {
	return GatewayError{Code: code, Message: msg}
}

func ToHTTPStatus(code Code) int {
	switch code {
	case CodeInvalidInput, CodeInvalidRequest:
		return http.StatusBadRequest
	case CodeUnauthorized:
		return http.StatusUnauthorized
	case CodeNotFound:
		return http.StatusNotFound
	case CodeConflict:
		return http.StatusConflict
	case CodeInvalidConsent, CodeMissingConsent:
		return http.StatusForbidden
	case CodePolicyViolation:
		return http.StatusPreconditionFailed
	case CodeRegistryTimeout:
		return http.StatusGatewayTimeout
	default:
		return http.StatusInternalServerError
	}
}
