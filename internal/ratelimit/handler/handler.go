package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"credo/internal/platform/middleware"
	"credo/internal/ratelimit/models"
	"credo/internal/transport/httputil"
	dErrors "credo/pkg/domain-errors"
)

// Service defines the interface for rate limiting operations.
// Handlers depend on this interface, not the concrete service.
type Service interface {
	// Allowlist management (admin operations)
	AddToAllowlist(ctx context.Context, req *models.AddAllowlistRequest, adminUserID string) (*models.AllowlistEntry, error)
	RemoveFromAllowlist(ctx context.Context, req *models.RemoveAllowlistRequest) error
	ListAllowlist(ctx context.Context) ([]*models.AllowlistEntry, error)

	// Admin operations
	ResetRateLimit(ctx context.Context, req *models.ResetRateLimitRequest) error
}

// Handler handles rate limit admin endpoints.
// Per PRD-017 FR-4: Admin endpoints for allowlist management.
type Handler struct {
	service Service
	logger  *slog.Logger
}

// New creates a new rate limit Handler.
func New(service Service, logger *slog.Logger) *Handler {
	return &Handler{
		service: service,
		logger:  logger,
	}
}

// RegisterAdmin registers admin routes for rate limit management.
// Per PRD-017 FR-4: POST /admin/rate-limit/allowlist
func (h *Handler) RegisterAdmin(r chi.Router) {
	r.Post("/admin/rate-limit/allowlist", h.HandleAddAllowlist)
	r.Delete("/admin/rate-limit/allowlist", h.HandleRemoveAllowlist)
	r.Get("/admin/rate-limit/allowlist", h.HandleListAllowlist)
	r.Post("/admin/rate-limit/reset", h.HandleResetRateLimit)
}

// HandleAddAllowlist implements POST /admin/rate-limit/allowlist.
// Per PRD-017 FR-4: Add IP or user to allowlist.
//
// Input: { "type": "ip", "identifier": "192.168.1.100", "reason": "...", "expires_at": "..." }
// Output: { "allowlisted": true, "identifier": "192.168.1.100", "expires_at": "..." }
//
// TODO: Implement this handler
// 1. Decode JSON request body
// 2. Validate request
// 3. Get admin user ID from context (set by auth middleware)
// 4. Call service.AddToAllowlist
// 5. Return AllowlistEntryResponse
func (h *Handler) HandleAddAllowlist(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)

	var req models.AddAllowlistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.WarnContext(ctx, "failed to decode add allowlist request",
			"error", err,
			"request_id", requestID,
		)
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "Invalid JSON in request body"))
		return
	}

	// TODO: Implement - validate request, get admin user ID, call service
	// adminUserID := middleware.GetUserID(ctx)
	// entry, err := h.service.AddToAllowlist(ctx, &req, adminUserID)
	// if err != nil { ... }
	// httputil.WriteJSON(w, http.StatusOK, &models.AllowlistEntryResponse{...})

	httputil.WriteError(w, dErrors.New(dErrors.CodeInternal, "not implemented"))
}

// HandleRemoveAllowlist implements DELETE /admin/rate-limit/allowlist.
// Per PRD-017 FR-4: Remove IP or user from allowlist.
//
// Input: { "type": "ip", "identifier": "192.168.1.100" }
// Output: 204 No Content
//
// TODO: Implement this handler
func (h *Handler) HandleRemoveAllowlist(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)

	var req models.RemoveAllowlistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.WarnContext(ctx, "failed to decode remove allowlist request",
			"error", err,
			"request_id", requestID,
		)
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "Invalid JSON in request body"))
		return
	}

	// TODO: Implement - validate request, call service
	// err := h.service.RemoveFromAllowlist(ctx, &req)
	// if err != nil { ... }
	// w.WriteHeader(http.StatusNoContent)

	httputil.WriteError(w, dErrors.New(dErrors.CodeInternal, "not implemented"))
}

// HandleListAllowlist implements GET /admin/rate-limit/allowlist.
// Returns all active allowlist entries.
//
// Output: [{ "type": "ip", "identifier": "...", ... }, ...]
//
// TODO: Implement this handler
func (h *Handler) HandleListAllowlist(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)

	// TODO: Implement
	// entries, err := h.service.ListAllowlist(ctx)
	// if err != nil { ... }
	// httputil.WriteJSON(w, http.StatusOK, entries)

	h.logger.InfoContext(ctx, "list allowlist called", "request_id", requestID)
	httputil.WriteError(w, dErrors.New(dErrors.CodeInternal, "not implemented"))
}

// HandleResetRateLimit implements POST /admin/rate-limit/reset.
// Per PRD-017 TR-1: Admin reset operation.
//
// Input: { "type": "ip", "identifier": "192.168.1.100", "class": "auth" }
// Output: 204 No Content
//
// TODO: Implement this handler
func (h *Handler) HandleResetRateLimit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)

	var req models.ResetRateLimitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.WarnContext(ctx, "failed to decode reset rate limit request",
			"error", err,
			"request_id", requestID,
		)
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "Invalid JSON in request body"))
		return
	}

	// TODO: Implement
	// err := h.service.ResetRateLimit(ctx, &req)
	// if err != nil { ... }
	// w.WriteHeader(http.StatusNoContent)

	httputil.WriteError(w, dErrors.New(dErrors.CodeInternal, "not implemented"))
}

// Ensure Handler has no unused imports
var (
	_ = httputil.WriteJSON
)
