package httptransport

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"id-gateway/internal/platform/middleware"
	"id-gateway/pkg/errors"
	httpErrors "id-gateway/pkg/http-errors"
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
	var domainErr errors.DomainError
	if errors.As(err, &domainErr) {
		status := domainCodeToHTTPStatus(domainErr.Code)
		code := domainCodeToHTTPCode(domainErr.Code)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": code,
		})
		return
	}

	// Fallback to legacy http errors (for backward compatibility)
	gw, ok := err.(httpErrors.GatewayError)
	status := http.StatusInternalServerError
	code := string(httpErrors.CodeInternal)
	if ok {
		status = httpErrors.ToHTTPStatus(gw.Code)
		code = string(gw.Code)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": code,
	})
}

// domainCodeToHTTPStatus translates domain error codes to HTTP status codes.
func domainCodeToHTTPStatus(code errors.Code) int {
	switch code {
	case errors.CodeNotFound:
		return http.StatusNotFound
	case errors.CodeInvalidRequest, errors.CodeValidation:
		return http.StatusBadRequest
	case errors.CodeConflict:
		return http.StatusConflict
	case errors.CodeUnauthorized:
		return http.StatusUnauthorized
	case errors.CodeInvalidConsent, errors.CodeMissingConsent:
		return http.StatusForbidden
	case errors.CodePolicyViolation:
		return http.StatusPreconditionFailed
	case errors.CodeTimeout:
		return http.StatusGatewayTimeout
	case errors.CodeInternal:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

// domainCodeToHTTPCode translates domain error codes to HTTP error codes (for JSON response).
func domainCodeToHTTPCode(code errors.Code) string {
	switch code {
	case errors.CodeNotFound:
		return "not_found"
	case errors.CodeInvalidRequest:
		return "invalid_request"
	case errors.CodeValidation:
		return "invalid_input"
	case errors.CodeConflict:
		return "conflict"
	case errors.CodeUnauthorized:
		return "unauthorized"
	case errors.CodeInvalidConsent:
		return "invalid_consent"
	case errors.CodeMissingConsent:
		return "missing_consent"
	case errors.CodePolicyViolation:
		return "policy_violation"
	case errors.CodeTimeout:
		return "registry_timeout"
	case errors.CodeInternal:
		return "internal_error"
	default:
		return "internal_error"
	}
}

// writeJSONError writes a JSON error response with a custom error code and description.
func writeJSONError(w http.ResponseWriter, code httpErrors.Code, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             string(code),
		"error_description": description,
	})
}
