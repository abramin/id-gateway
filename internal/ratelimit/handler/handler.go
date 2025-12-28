package handler

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"credo/internal/ratelimit/models"
	"credo/pkg/platform/httputil"
	"credo/pkg/platform/middleware/auth"
	request "credo/pkg/platform/middleware/request"
)

type Service interface {
	AddToAllowlist(ctx context.Context, req *models.AddAllowlistRequest, adminUserID string) (*models.AllowlistEntry, error)
	RemoveFromAllowlist(ctx context.Context, req *models.RemoveAllowlistRequest) error
	ListAllowlist(ctx context.Context) ([]*models.AllowlistEntry, error)
	ResetRateLimit(ctx context.Context, req *models.ResetRateLimitRequest) error
}

type Handler struct {
	service Service
	logger  *slog.Logger
}

func New(service Service, logger *slog.Logger) *Handler {
	return &Handler{
		service: service,
		logger:  logger,
	}
}

func (h *Handler) RegisterAdmin(r chi.Router) {
	r.Post("/admin/rate-limit/allowlist", h.HandleAddAllowlist)
	r.Delete("/admin/rate-limit/allowlist", h.HandleRemoveAllowlist)
	r.Get("/admin/rate-limit/allowlist", h.HandleListAllowlist)
	r.Post("/admin/rate-limit/reset", h.HandleResetRateLimit)
}

// HandleAddAllowlist implements POST /admin/rate-limit/allowlist.
// Input: { "type": "ip", "identifier": "192.168.1.100", "reason": "...", "expires_at": "..." }
// Output: { "allowlisted": true, "identifier": "192.168.1.100", "expires_at": "..." }

func (h *Handler) HandleAddAllowlist(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	// Limit request body size to prevent DoS via large payloads
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64KB max

	req, ok := httputil.DecodeAndPrepare[models.AddAllowlistRequest](w, r, h.logger, ctx, requestID)
	if !ok {
		return
	}

	adminUserID := auth.GetUserID(ctx).String()
	entry, err := h.service.AddToAllowlist(ctx, req, adminUserID)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to add to allowlist",
			"error", err,
			"identifier", req.Identifier,
			"request_id", requestID,
		)
		httputil.WriteError(w, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, &models.AllowlistEntryResponse{
		Allowlisted: true,
		Identifier:  entry.Identifier.String(),
		ExpiresAt:   entry.ExpiresAt,
	})
}

// HandleRemoveAllowlist implements DELETE /admin/rate-limit/allowlist.
//
// Input: { "type": "ip", "identifier": "192.168.1.100" }
// Output: 204 No Content
//
// TODO: Implement this handler
func (h *Handler) HandleRemoveAllowlist(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	// Limit request body size to prevent DoS via large payloads
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64KB max

	req, ok := httputil.DecodeAndPrepare[models.RemoveAllowlistRequest](w, r, h.logger, ctx, requestID)
	if !ok {
		return
	}

	err := h.service.RemoveFromAllowlist(ctx, req)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to remove from allowlist",
			"error", err,
			"identifier", req.Identifier,
			"request_id", requestID,
		)
		httputil.WriteError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandleListAllowlist implements GET /admin/rate-limit/allowlist.
// Returns all active allowlist entries.
//
// Output: [{ "type": "ip", "identifier": "...", ... }, ...]
func (h *Handler) HandleListAllowlist(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	entries, err := h.service.ListAllowlist(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to list allowlist entries",
			"error", err,
			"request_id", requestID,
		)
		httputil.WriteError(w, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, entries)

	h.logger.InfoContext(ctx, "list allowlist called", "request_id", requestID)
}

// HandleResetRateLimit implements POST /admin/rate-limit/reset.
// Per PRD-017 TR-1: Admin reset operation.
//
// Input: { "type": "ip", "identifier": "192.168.1.100", "class": "auth" }
// Output: 204 No Content
func (h *Handler) HandleResetRateLimit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	// Limit request body size to prevent DoS via large payloads
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64KB max

	req, ok := httputil.DecodeAndPrepare[models.ResetRateLimitRequest](w, r, h.logger, ctx, requestID)
	if !ok {
		return
	}

	err := h.service.ResetRateLimit(ctx, req)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to reset rate limit",
			"error", err,
			"identifier", req.Identifier,
			"request_id", requestID,
		)
		httputil.WriteError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
