package domainerrors

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
	CodeInvalidGrant         Code = "invalid_grant"          // Invalid/expired/used authorization code or refresh token
	CodeInvalidClient        Code = "invalid_client"         // Client authentication failed
	CodeUnsupportedGrantType Code = "unsupported_grant_type" // Grant type not supported
	CodeInvalidRequest       Code = "invalid_request"        // Missing required parameter or malformed request
	CodeAccessDenied         Code = "access_denied"          // Resource owner or server denied request
)

// Error wraps domain or infrastructure failures with a stable code.
// It is transport-agnostic and can be used across service, store, and other layers.
type Error struct {
	Code    Code
	Message string
	Err     error
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return string(e.Code)
}

// Unwrap implements error unwrapping for error chains.
func (e *Error) Unwrap() error {
	return e.Err
}

// Is enables errors.Is() to match errors by code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return e.Code == t.Code
}

// New creates a new domain error with the given code and message.
func New(code Code, msg string) error {
	return &Error{Code: code, Message: msg}
}

// Wrap creates a new domain error wrapping an existing error.
// If the wrapped error is already a domain error, the original code is preserved.
func Wrap(err error, code Code, msg string) error {
	var existing *Error
	if errors.As(err, &existing) {
		// Preserve the original domain code, update message
		return &Error{Code: existing.Code, Message: msg, Err: err}
	}
	return &Error{Code: code, Message: msg, Err: err}
}

// HasCode checks if an error is a domain error with the given code.
func HasCode(err error, code Code) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Code == code
	}
	return false
}
