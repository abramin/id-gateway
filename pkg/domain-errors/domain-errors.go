package errors

import "errors"

// Code represents a domain error category independent of transport layer.
// These codes describe what went wrong in business logic terms, not HTTP terms.
type Code string

const (
	CodeNotFound           Code = "not_found"
	CodeBadRequest         Code = "bad_request"
	CodeInvalidInput       Code = "invalid_input"
	CodeValidation         Code = "validation_failed"
	CodeInternal           Code = "internal_error"
	CodeConflict           Code = "conflict"
	CodeUnauthorized       Code = "unauthorized"
	CodeForbidden          Code = "forbidden"
	CodeInvalidConsent     Code = "invalid_consent"
	CodeMissingConsent     Code = "missing_consent"
	CodePolicyViolation    Code = "policy_violation"
	CodeTimeout            Code = "timeout"
	CodeInvariantViolation Code = "invariant_violation"

	// OAuth 2.0 error codes (RFC 6749 §5.2)
	CodeInvalidGrant          Code = "invalid_grant"           // Invalid/expired/used authorization code or refresh token
	CodeInvalidClient         Code = "invalid_client"          // Client authentication failed
	CodeUnsupportedGrantType  Code = "unsupported_grant_type"  // Grant type not supported
	CodeInvalidRequest        Code = "invalid_request"         // Missing required parameter or malformed request
	CodeAccessDenied          Code = "access_denied"           // Resource owner or server denied request
)

// DomainError wraps domain or infrastructure failures with a stable code.
// It is transport-agnostic and can be used across service, store, and other layers.
type DomainError struct {
	Code    Code
	Message string
	Err     error
}

func (e DomainError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return string(e.Code)
}

func (e DomainError) Unwrap() error {
	return e.Err
}

// New creates a new DomainError with the given code and message.
func New(code Code, msg string) DomainError {
	return DomainError{Code: code, Message: msg}
}

// Wrap creates a new DomainError wrapping an existing error.
func Wrap(err error, code Code, msg string) DomainError {
	// Preserve an existing domain code if the cause is already a DomainError
	var de DomainError
	if errors.As(err, &de) {
		de.Message = msg
		de.Err = err
		return de
	}

	return DomainError{Code: code, Message: msg, Err: err}
}

// Is checks if an error is a DomainError with the given code.
func Is(err error, code Code) bool {
	var de DomainError
	if errors.As(err, &de) {
		return de.Code == code
	}
	return false
}
