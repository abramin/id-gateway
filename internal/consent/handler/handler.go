package handler

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	consentmetrics "credo/internal/consent/metrics"
	"credo/internal/consent/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/httputil"
	adminmw "credo/pkg/platform/middleware/admin"
	"credo/pkg/requestcontext"
)

// Service defines the interface for consent operations.
// Returns domain objects, not HTTP response DTOs.
type Service interface {
	Grant(ctx context.Context, userID id.UserID, purposes []models.Purpose) ([]*models.Record, error)
	Revoke(ctx context.Context, userID id.UserID, purposes []models.Purpose) ([]*models.Record, error)
	RevokeAll(ctx context.Context, userID id.UserID) (int, error)
	DeleteAll(ctx context.Context, userID id.UserID) error
	List(ctx context.Context, userID id.UserID, filter *models.RecordFilter) ([]*models.Record, error)
}

// Handler wires HTTP consent endpoints to the consent service.
type Handler struct {
	logger  *slog.Logger
	consent Service
	metrics *consentmetrics.Metrics
}

// New constructs a consent handler with dependencies wired.
func New(consent Service, logger *slog.Logger, metrics *consentmetrics.Metrics) *Handler {
	return &Handler{
		logger:  logger,
		consent: consent,
		metrics: metrics,
	}
}

// HandleGrantConsent grants consent for the authenticated user.
// It validates input, invokes the service, and returns grant details.
func (h *Handler) HandleGrantConsent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := time.Now()
	defer func() {
		if h.metrics != nil {
			h.metrics.ObserveConsentGrantLatency(time.Since(start).Seconds())
		}
	}()

	requestID := requestcontext.RequestID(ctx)
	userID, err := httputil.RequireUserID(ctx, h.logger, requestID)
	if err != nil {
		httputil.WriteError(w, err)
		return
	}

	grantReq, ok := httputil.DecodeAndPrepare[GrantRequest](w, r, h.logger, ctx, requestID)
	if !ok {
		return
	}
	purposes, err := grantReq.ToPurposes()
	if err != nil {
		httputil.WriteError(w, dErrors.New(dErrors.CodeValidation, err.Error()))
		return
	}

	records, err := h.consent.Grant(ctx, userID, purposes)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to grant consent",
			"request_id", requestID,
			"error", err,
		)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, toGrantResponse(records, requestcontext.Now(ctx)))
}

// HandleRevokeConsent revokes consent for the authenticated user.
// It validates input, invokes the service, and returns revocation details.
func (h *Handler) HandleRevokeConsent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := requestcontext.RequestID(ctx)
	userID, err := httputil.RequireUserID(ctx, h.logger, requestID)
	if err != nil {
		httputil.WriteError(w, err)
		return
	}

	revokeReq, ok := httputil.DecodeAndPrepare[RevokeRequest](w, r, h.logger, ctx, requestID)
	if !ok {
		return
	}
	purposes, err := revokeReq.ToPurposes()
	if err != nil {
		httputil.WriteError(w, dErrors.New(dErrors.CodeValidation, err.Error()))
		return
	}

	records, err := h.consent.Revoke(ctx, userID, purposes)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to revoke consent",
			"request_id", requestID,
			"error", err,
		)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, toRevokeResponse(records, requestcontext.Now(ctx)))
}

// HandleRevokeAllConsents revokes all consents for the authenticated user.
func (h *Handler) HandleRevokeAllConsents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := requestcontext.RequestID(ctx)
	userID, err := httputil.RequireUserID(ctx, h.logger, requestID)
	if err != nil {
		httputil.WriteError(w, err)
		return
	}

	count, err := h.consent.RevokeAll(ctx, userID)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to revoke all consents",
			"request_id", requestID,
			"error", err,
		)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, &RevokeResponse{
		Revoked: nil,
		Message: formatActionMessage("Consent revoked for %d purpose", count),
	})
}

// HandleAdminRevokeAllConsents revokes all consents for a user by admin action.
func (h *Handler) HandleAdminRevokeAllConsents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := requestcontext.RequestID(ctx)
	if !adminmw.IsAdminRequest(ctx) {
		httputil.WriteError(w, dErrors.New(dErrors.CodeUnauthorized, "admin token required"))
		return
	}
	userIDStr := chi.URLParam(r, "user_id")
	userID, err := id.ParseUserID(userIDStr)
	if err != nil {
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid user id"))
		return
	}

	count, err := h.consent.RevokeAll(ctx, userID)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to revoke all consents (admin)",
			"request_id", requestID,
			"user_id", userID,
			"error", err,
		)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, &RevokeResponse{
		Revoked: nil,
		Message: formatActionMessage("Consent revoked for %d purpose", count),
	})
}

// HandleDeleteAllConsents deletes all consent records for the authenticated user.
func (h *Handler) HandleDeleteAllConsents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := requestcontext.RequestID(ctx)
	userID, err := httputil.RequireUserID(ctx, h.logger, requestID)
	if err != nil {
		httputil.WriteError(w, err)
		return
	}

	if err := h.consent.DeleteAll(ctx, userID); err != nil {
		h.logger.ErrorContext(ctx, "failed to delete all consents",
			"request_id", requestID,
			"error", err,
		)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "All consents deleted",
	})
}

// HandleGetConsents lists consent records for the authenticated user.
func (h *Handler) HandleGetConsents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := requestcontext.RequestID(ctx)
	userID, err := httputil.RequireUserID(ctx, h.logger, requestID)
	if err != nil {
		httputil.WriteError(w, err)
		return
	}

	filter, err := parseRecordFilter(r.URL.Query().Get("status"), r.URL.Query().Get("purpose"))
	if err != nil {
		httputil.WriteError(w, err)
		return
	}

	records, err := h.consent.List(ctx, userID, filter)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to list consent",
			"request_id", requestID,
			"error", err,
		)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, toListResponse(records, requestcontext.Now(ctx)))
}

// parseRecordFilter converts query parameters into a domain RecordFilter.
// Returns nil if no filters are specified.
// Returns validation error if status or purpose values are invalid.
func parseRecordFilter(status, purpose string) (*models.RecordFilter, error) {
	status = strings.TrimSpace(status)
	purpose = strings.TrimSpace(purpose)

	filter := &models.RecordFilter{}

	if status != "" {
		parsedStatus, err := models.ParseStatus(status)
		if err != nil {
			return nil, dErrors.New(dErrors.CodeValidation, "invalid status filter")
		}
		filter.Status = &parsedStatus
	}

	if purpose != "" {
		parsedPurpose, err := models.ParsePurpose(purpose)
		if err != nil {
			return nil, dErrors.New(dErrors.CodeValidation, "invalid purpose filter")
		}
		filter.Purpose = &parsedPurpose
	}

	if filter.Status == nil && filter.Purpose == nil {
		return nil, nil
	}

	return filter, nil
}
