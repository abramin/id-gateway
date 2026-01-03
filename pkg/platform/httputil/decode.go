package httputil

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	dErrors "credo/pkg/domain-errors"
)

// DecodeJSON decodes a JSON request body into the target type.
// Returns the decoded value and true on success.
// On failure, writes an error response and returns nil, false.
//
// Usage:
//
//	req, ok := httputil.DecodeJSON[models.GrantRequest](w, r, h.logger, ctx, requestID)
//	if !ok {
//	    return
//	}
func DecodeJSON[T any](w http.ResponseWriter, r *http.Request, logger *slog.Logger, ctx context.Context, requestID string) (*T, bool) {
	var req T
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.WarnContext(ctx, "failed to decode request body",
			"error", err,
			"request_id", requestID,
		)
		WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid request body"))
		return nil, false
	}
	return &req, true
}

// Validatable is implemented by request types that support validation.
type Validatable interface {
	Validate() error
}

// Normalizable is implemented by request types that support normalization.
type Normalizable interface {
	Normalize()
}

// Sanitizable is implemented by request types that support sanitization.
type Sanitizable interface {
	Sanitize()
}

// PrepareRequest sanitizes, normalizes, and validates a request.
// This is a helper for the common pattern of request preparation.
func PrepareRequest(req any) error {
	if s, ok := req.(Sanitizable); ok {
		s.Sanitize()
	}
	if n, ok := req.(Normalizable); ok {
		n.Normalize()
	}
	if v, ok := req.(Validatable); ok {
		return v.Validate()
	}
	return nil
}

// DecodeAndPrepare combines JSON decoding with request preparation.
// It decodes the JSON body, then calls Sanitize(), Normalize(), and Validate()
// if the target type implements those interfaces.
//
// Usage:
//
//	req, ok := httputil.DecodeAndPrepare[models.GrantRequest](w, r, h.logger, ctx, requestID)
//	if !ok {
//	    return
//	}
func DecodeAndPrepare[T any](w http.ResponseWriter, r *http.Request, logger *slog.Logger, ctx context.Context, requestID string) (*T, bool) {
	req, ok := DecodeJSON[T](w, r, logger, ctx, requestID)
	if !ok {
		return nil, false
	}

	if err := PrepareRequest(req); err != nil {
		logger.WarnContext(ctx, "invalid request",
			"error", err,
			"request_id", requestID,
		)
		// Preserve original error code if it's already a domain error
		var domainErr *dErrors.Error
		if errors.As(err, &domainErr) {
			WriteError(w, err)
		} else {
			WriteError(w, dErrors.New(dErrors.CodeValidation, err.Error()))
		}
		return nil, false
	}

	return req, true
}
