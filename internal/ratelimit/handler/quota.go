package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"credo/internal/ratelimit/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/httputil"
	"credo/pkg/requestcontext"
)

// QuotaService defines the quota operations interface (PRD-017 FR-5)
type QuotaService interface {
	Check(ctx context.Context, apiKeyID id.APIKeyID) (*models.APIKeyQuota, error)
	Reset(ctx context.Context, apiKeyID id.APIKeyID) error
	List(ctx context.Context) ([]*models.APIKeyQuota, error)
	UpdateTier(ctx context.Context, apiKeyID id.APIKeyID, tier models.QuotaTier) error
}

// QuotaHandler handles quota management endpoints (PRD-017 FR-5)
type QuotaHandler struct {
	service QuotaService
	logger  *slog.Logger
}

// NewQuotaHandler creates a new quota handler
func NewQuotaHandler(service QuotaService, logger *slog.Logger) *QuotaHandler {
	return &QuotaHandler{
		service: service,
		logger:  logger,
	}
}

// RegisterAdmin registers quota routes with the router
func (h *QuotaHandler) RegisterAdmin(r chi.Router) {
	r.Get("/admin/rate-limit/quota/{api_key}", h.HandleGetQuota)
	r.Post("/admin/rate-limit/quota/{api_key}/reset", h.HandleResetQuota)
	r.Get("/admin/rate-limit/quotas", h.HandleListQuotas)
	r.Put("/admin/rate-limit/quota/{api_key}/tier", h.HandleUpdateQuotaTier)
}

// requireAPIKeyFromPath parses api_key from URL path parameter.
// Returns the raw string (for logging) and parsed ID.
// Returns false if parsing fails (error response already written).
func (h *QuotaHandler) requireAPIKeyFromPath(r *http.Request, w http.ResponseWriter, requestID string) (string, id.APIKeyID, bool) {
	ctx := r.Context()
	apiKeyStr := chi.URLParam(r, "api_key")
	apiKeyID, err := id.ParseAPIKeyID(apiKeyStr)
	if err != nil {
		h.logger.WarnContext(ctx, "invalid api_key format",
			"api_key", apiKeyStr,
			"request_id", requestID,
		)
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid api_key format"))
		return "", "", false
	}
	return apiKeyStr, apiKeyID, true
}

// toQuotaUsageResponse converts a quota model to a response DTO
func toQuotaUsageResponse(quota *models.APIKeyQuota) models.QuotaUsageResponse {
	remaining := max(quota.MonthlyLimit-quota.CurrentUsage, 0)
	return models.QuotaUsageResponse{
		APIKeyID:  quota.APIKeyID.String(),
		Tier:      string(quota.Tier),
		Usage:     quota.CurrentUsage,
		Limit:     quota.MonthlyLimit,
		Remaining: remaining,
		ResetAt:   quota.PeriodEnd,
	}
}

// HandleGetQuota implements GET /admin/rate-limit/quota/:api_key
// Returns the quota usage for a specific API key.
func (h *QuotaHandler) HandleGetQuota(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := requestcontext.RequestID(ctx)

	apiKeyStr, apiKeyID, ok := h.requireAPIKeyFromPath(r, w, requestID)
	if !ok {
		return
	}

	quota, err := h.service.Check(ctx, apiKeyID)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to get quota",
			"error", err,
			"api_key", apiKeyStr,
			"request_id", requestID,
		)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, toQuotaUsageResponse(quota))
}

// HandleResetQuota implements POST /admin/rate-limit/quota/:api_key/reset
// Resets the quota usage for a specific API key.
func (h *QuotaHandler) HandleResetQuota(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := requestcontext.RequestID(ctx)

	apiKeyStr, apiKeyID, ok := h.requireAPIKeyFromPath(r, w, requestID)
	if !ok {
		return
	}

	// Parse optional reason from body (don't require body)
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req models.ResetQuotaRequest
	_ = json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck // reason is optional

	if err := h.service.Reset(ctx, apiKeyID); err != nil {
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
func (h *QuotaHandler) HandleListQuotas(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := requestcontext.RequestID(ctx)

	quotas, err := h.service.List(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to list quotas",
			"error", err,
			"request_id", requestID,
		)
		httputil.WriteError(w, err)
		return
	}

	responses := make([]models.QuotaUsageResponse, 0, len(quotas))
	for _, q := range quotas {
		responses = append(responses, toQuotaUsageResponse(q))
	}

	httputil.WriteJSON(w, http.StatusOK, responses)
}

// HandleUpdateQuotaTier implements PUT /admin/rate-limit/quota/:api_key/tier
// Updates the quota tier for a specific API key.
func (h *QuotaHandler) HandleUpdateQuotaTier(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := requestcontext.RequestID(ctx)

	apiKeyStr, apiKeyID, ok := h.requireAPIKeyFromPath(r, w, requestID)
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)

	req, ok := httputil.DecodeAndPrepare[models.UpdateQuotaTierRequest](w, r, h.logger, ctx, requestID)
	if !ok {
		return
	}

	tier := models.QuotaTier(req.Tier) // Already normalized by DecodeAndPrepare
	if err := h.service.UpdateTier(ctx, apiKeyID, tier); err != nil {
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
