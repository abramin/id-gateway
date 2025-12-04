package httptransport

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	httpErrors "id-gateway/pkg/http-errors"
	"id-gateway/internal/platform/middleware"
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

// writeError centralizes domain error translation to HTTP responses for future
// handlers. Keeping it here ensures consistent JSON error envelopes.
func writeError(w http.ResponseWriter, err error) {
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

// writeJSONError writes a JSON error response with a custom error code and description.
func writeJSONError(w http.ResponseWriter, code httpErrors.Code, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             string(code),
		"error_description": description,
	})
}
