package httptransport

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"id-gateway/internal/platform/middleware"
	dErrors "id-gateway/pkg/domain-errors"
)

// Handler is the thin HTTP layer. It should delegate to domain services without
// embedding business logic so transport concerns remain isolated.
type Handler struct {
	regulatedMode bool
	logger        *slog.Logger
}

func NewHandler(regulatedMode bool, logger *slog.Logger) *Handler {
	return &Handler{
		regulatedMode: regulatedMode,
		logger:        logger,
	}
}

// NewRouter wires all public endpoints with middleware.
// Uses chi router for better middleware support and routing.
func NewRouter(h *Handler, logger *slog.Logger) http.Handler {
	r := chi.NewRouter()

	// Phase 1 Middleware Stack
	r.Use(middleware.Recovery(logger))
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger(logger))
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(middleware.ContentTypeJSON)

	// Evidence endpoints
	r.Post("/vc/issue", h.handleVCIssue)
	r.Post("/vc/verify", h.handleVCVerify)

	// Registry endpoints
	r.Post("/registry/citizen", h.handleRegistryCitizen)
	r.Post("/registry/sanctions", h.handleRegistrySanctions)

	// Decision endpoint
	r.Post("/decision/evaluate", h.handleDecisionEvaluate)

	// User data rights endpoints
	r.Get("/me/data-export", h.handleDataExport)
	r.Delete("/me", h.handleDataDeletion)

	return r
}

func (h *Handler) notImplemented(w http.ResponseWriter, endpoint string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message":  "TODO: implement handler",
		"endpoint": endpoint,
	})
}

// writeError centralizes domain error translation to HTTP responses.
// It translates transport-agnostic domain errors into HTTP status codes and error responses.
func writeError(w http.ResponseWriter, err error) {
	// Try domain error first (new approach)
	var domainErr dErrors.DomainError
	if errors.As(err, &domainErr) {
		status := domainCodeToHTTPStatus(domainErr.Code)
		code := domainCodeToHTTPCode(domainErr.Code)
		response := map[string]string{
			"error": code,
		}
		if domainErr.Message != "" {
			response["error_description"] = domainErr.Message
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(response)
		return
	}

	// Fallback for unexpected errors
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": domainCodeToHTTPCode(dErrors.CodeInternal),
	})
}

// domainCodeToHTTPStatus translates domain error codes to HTTP status codes.
func domainCodeToHTTPStatus(code dErrors.Code) int {
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

// domainCodeToHTTPCode translates domain error codes to HTTP error codes (for JSON response).
func domainCodeToHTTPCode(code dErrors.Code) string {
	switch code {
	case dErrors.CodeNotFound:
		return "not_found"
	case dErrors.CodeBadRequest:
		return "invalid_request"
	case dErrors.CodeValidation:
		return "invalid_input"
	case dErrors.CodeInvalidInput:
		return "invalid_input"
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
