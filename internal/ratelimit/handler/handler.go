package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"credo/internal/ratelimit/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
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

// QuotaService defines the quota operations interface (PRD-017 FR-5)
type QuotaService interface {
	Check(ctx context.Context, apiKeyID id.APIKeyID) (*models.APIKeyQuota, error)
	Reset(ctx context.Context, apiKeyID id.APIKeyID) error
	List(ctx context.Context) ([]*models.APIKeyQuota, error)
	UpdateTier(ctx context.Context, apiKeyID id.APIKeyID, tier models.QuotaTier) error
}

type Handler struct {
	service      Service
	quotaService QuotaService
	logger       *slog.Logger
}

func New(service Service, logger *slog.Logger) *Handler {
	return &Handler{
		service: service,
		logger:  logger,
	}
}

// WithQuotaService adds the quota service to the handler (PRD-017 FR-5)
func (h *Handler) WithQuotaService(qs QuotaService) *Handler {
	h.quotaService = qs
	return h
}

func (h *Handler) RegisterAdmin(r chi.Router) {
	r.Post("/admin/rate-limit/allowlist", h.HandleAddAllowlist)
	r.Delete("/admin/rate-limit/allowlist", h.HandleRemoveAllowlist)
	r.Get("/admin/rate-limit/allowlist", h.HandleListAllowlist)
	r.Post("/admin/rate-limit/reset", h.HandleResetRateLimit)

	// PRD-017 FR-5: Partner API Quota endpoints
	r.Get("/admin/rate-limit/quota/{api_key}", h.HandleGetQuota)
	r.Post("/admin/rate-limit/quota/{api_key}/reset", h.HandleResetQuota)
	r.Get("/admin/rate-limit/quotas", h.HandleListQuotas)
	r.Put("/admin/rate-limit/quota/{api_key}/tier", h.HandleUpdateQuotaTier)
}

// HandleAddAllowlist implements POST /admin/rate-limit/allowlist.
// Input: { "type": "ip", "identifier": "192.168.1.100", "reason": "...", "expires_at": "..." }
// Output: { "allowlisted": true, "identifier": "192.168.1.100", "expires_at": "..." }

func (h *Handler) HandleAddAllowlist(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	// Limit request body size to prevent DoS via large payloads
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64KB max

	var req models.AddAllowlistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.WarnContext(ctx, "failed to decode add allowlist request",
			"error", err,
			"request_id", requestID,
		)
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "Invalid JSON in request body"))
		return
	}

	adminUserID := auth.GetUserID(ctx)
	entry, err := h.service.AddToAllowlist(ctx, &req, adminUserID)
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
		Identifier:  entry.Identifier,
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

	var req models.RemoveAllowlistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.WarnContext(ctx, "failed to decode remove allowlist request",
			"error", err,
			"request_id", requestID,
		)
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "Invalid JSON in request body"))
		return
	}

	err := h.service.RemoveFromAllowlist(ctx, &req)
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
	err := h.service.ResetRateLimit(ctx, &req)
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

// =============================================================================
// PRD-017 FR-5: Partner API Quota Handlers
// =============================================================================

// HandleGetQuota implements GET /admin/rate-limit/quota/:api_key
// Returns the quota usage for a specific API key.
func (h *Handler) HandleGetQuota(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	if h.quotaService == nil {
		httputil.WriteError(w, dErrors.New(dErrors.CodeInternal, "quota service not configured"))
		return
	}

	apiKeyStr := chi.URLParam(r, "api_key")
	apiKeyID, err := id.ParseAPIKeyID(apiKeyStr)
	if err != nil {
		h.logger.WarnContext(ctx, "invalid api_key format",
			"api_key", apiKeyStr,
			"request_id", requestID,
		)
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid api_key format"))
		return
	}

	quota, err := h.quotaService.Check(ctx, apiKeyID)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to get quota",
			"error", err,
			"api_key", apiKeyStr,
			"request_id", requestID,
		)
		httputil.WriteError(w, err)
		return
	}

	remaining := quota.MonthlyLimit - quota.CurrentUsage
	if remaining < 0 {
		remaining = 0
	}

	response := models.QuotaUsageResponse{
		APIKeyID:  apiKeyStr,
		Tier:      string(quota.Tier),
		Usage:     quota.CurrentUsage,
		Limit:     quota.MonthlyLimit,
		Remaining: remaining,
		ResetAt:   quota.PeriodEnd,
	}

	httputil.WriteJSON(w, http.StatusOK, response)
}

// HandleResetQuota implements POST /admin/rate-limit/quota/:api_key/reset
// Resets the quota usage for a specific API key.
func (h *Handler) HandleResetQuota(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	if h.quotaService == nil {
		httputil.WriteError(w, dErrors.New(dErrors.CodeInternal, "quota service not configured"))
		return
	}

	apiKeyStr := chi.URLParam(r, "api_key")
	apiKeyID, err := id.ParseAPIKeyID(apiKeyStr)
	if err != nil {
		h.logger.WarnContext(ctx, "invalid api_key format",
			"api_key", apiKeyStr,
			"request_id", requestID,
		)
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid api_key format"))
		return
	}

	// Parse optional reason from body (don't require body)
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req models.ResetQuotaRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // Ignore errors - reason is optional

	if err := h.quotaService.Reset(ctx, apiKeyID); err != nil {
		h.logger.ErrorContext(ctx, "failed to reset quota",
			"error", err,
			"api_key", apiKeyStr,
			"reason", req.Reason,
			"request_id", requestID,
		)
		httputil.WriteError(w, err)
		return
	}

	h.logger.InfoContext(ctx, "quota reset",
		"api_key", apiKeyStr,
		"reason", req.Reason,
		"request_id", requestID,
	)

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "reset"})
}

// HandleListQuotas implements GET /admin/rate-limit/quotas
// Returns all quota records.
func (h *Handler) HandleListQuotas(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	if h.quotaService == nil {
		httputil.WriteError(w, dErrors.New(dErrors.CodeInternal, "quota service not configured"))
		return
	}

	quotas, err := h.quotaService.List(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to list quotas",
			"error", err,
			"request_id", requestID,
		)
		httputil.WriteError(w, err)
		return
	}

	// Convert to response format
	responses := make([]models.QuotaUsageResponse, 0, len(quotas))
	for _, q := range quotas {
		remaining := q.MonthlyLimit - q.CurrentUsage
		if remaining < 0 {
			remaining = 0
		}
		responses = append(responses, models.QuotaUsageResponse{
			APIKeyID:  q.APIKeyID.String(),
			Tier:      string(q.Tier),
			Usage:     q.CurrentUsage,
			Limit:     q.MonthlyLimit,
			Remaining: remaining,
			ResetAt:   q.PeriodEnd,
		})
	}

	httputil.WriteJSON(w, http.StatusOK, responses)
}

// HandleUpdateQuotaTier implements PUT /admin/rate-limit/quota/:api_key/tier
// Updates the quota tier for a specific API key.
func (h *Handler) HandleUpdateQuotaTier(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	if h.quotaService == nil {
		httputil.WriteError(w, dErrors.New(dErrors.CodeInternal, "quota service not configured"))
		return
	}

	apiKeyStr := chi.URLParam(r, "api_key")
	apiKeyID, err := id.ParseAPIKeyID(apiKeyStr)
	if err != nil {
		h.logger.WarnContext(ctx, "invalid api_key format",
			"api_key", apiKeyStr,
			"request_id", requestID,
		)
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid api_key format"))
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req models.UpdateQuotaTierRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.WarnContext(ctx, "failed to decode update tier request",
			"error", err,
			"request_id", requestID,
		)
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "Invalid JSON in request body"))
		return
	}

	if err := req.Validate(); err != nil {
		httputil.WriteError(w, err)
		return
	}

	tier := models.QuotaTier(strings.TrimSpace(strings.ToLower(req.Tier)))
	if err := h.quotaService.UpdateTier(ctx, apiKeyID, tier); err != nil {
		h.logger.ErrorContext(ctx, "failed to update tier",
			"error", err,
			"api_key", apiKeyStr,
			"tier", tier,
			"request_id", requestID,
		)
		httputil.WriteError(w, err)
		return
	}

	h.logger.InfoContext(ctx, "tier updated",
		"api_key", apiKeyStr,
		"tier", tier,
		"request_id", requestID,
	)

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "updated", "tier": string(tier)})
}
