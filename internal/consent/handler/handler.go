package handler

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	consentmetrics "credo/internal/consent/metrics"
	"credo/internal/consent/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/httputil"
	auth "credo/pkg/platform/middleware/auth"
	request "credo/pkg/platform/middleware/request"
	"credo/pkg/platform/middleware/requesttime"
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

	requestID := request.GetRequestID(ctx)
	userID, err := h.requireUserID(ctx, requestID)
	if err != nil {
		httputil.WriteError(w, err)
		return
	}

	grantReq, ok := httputil.DecodeAndPrepare[models.GrantRequest](w, r, h.logger, ctx, requestID)
	if !ok {
		return
	}

	records, err := h.consent.Grant(ctx, userID, grantReq.Purposes)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to grant consent",
			"request_id", requestID,
			"error", err,
		)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, toGrantResponse(records, requesttime.Now(ctx)))
}

// HandleRevokeConsent revokes consent for the authenticated user.
// It validates input, invokes the service, and returns revocation details.
func (h *Handler) HandleRevokeConsent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)
	userID, err := h.requireUserID(ctx, requestID)
	if err != nil {
		httputil.WriteError(w, err)
		return
	}

	revokeReq, ok := httputil.DecodeAndPrepare[models.RevokeRequest](w, r, h.logger, ctx, requestID)
	if !ok {
		return
	}

	records, err := h.consent.Revoke(ctx, userID, revokeReq.Purposes)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to revoke consent",
			"request_id", requestID,
			"error", err,
		)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, toRevokeResponse(records, requesttime.Now(ctx)))
}

// HandleAdminRevokeAllConsents revokes all consents for a user by admin action.
func (h *Handler) HandleAdminRevokeAllConsents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)
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

	httputil.WriteJSON(w, http.StatusOK, &models.RevokeResponse{
		Revoked: nil,
		Message: formatActionMessage("Consent revoked for %d purpose", count),
	})
}

// HandleDeleteAllConsents deletes all consent records for the authenticated user.
func (h *Handler) HandleDeleteAllConsents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)
	userID, err := h.requireUserID(ctx, requestID)
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
	requestID := request.GetRequestID(ctx)
	userID, err := h.requireUserID(ctx, requestID)
	if err != nil {
		httputil.WriteError(w, err)
		return
	}

	filter, err := models.ParseRecordFilter(
		r.URL.Query().Get("status"),
		r.URL.Query().Get("purpose"),
	)
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

	httputil.WriteJSON(w, http.StatusOK, toListResponse(records, requesttime.Now(ctx)))
}

// Response mapping functions - convert domain objects to HTTP DTOs

func toGrantResponse(records []*models.Record, now time.Time) *models.GrantResponse {
	granted := make([]*models.Grant, 0, len(records))
	for _, record := range records {
		granted = append(granted, &models.Grant{
			Purpose:   record.Purpose,
			GrantedAt: record.GrantedAt,
			ExpiresAt: record.ExpiresAt,
			Status:    record.ComputeStatus(now),
		})
	}
	return &models.GrantResponse{
		Granted: granted,
		Message: formatActionMessage("Consent granted for %d purpose", len(records)),
	}
}

func toRevokeResponse(records []*models.Record, now time.Time) *models.RevokeResponse {
	revoked := make([]*models.Revoked, 0, len(records))
	for _, record := range records {
		if record.RevokedAt != nil {
			revoked = append(revoked, &models.Revoked{
				Purpose:   record.Purpose,
				RevokedAt: *record.RevokedAt,
				Status:    record.ComputeStatus(now),
			})
		}
	}
	return &models.RevokeResponse{
		Revoked: revoked,
		Message: formatActionMessage("Consent revoked for %d purpose", len(revoked)),
	}
}

func toListResponse(records []*models.Record, now time.Time) *models.ListResponse {
	consents := make([]*models.ConsentWithStatus, 0, len(records))
	for _, record := range records {
		consents = append(consents, &models.ConsentWithStatus{
			Consent: models.Consent{
				ID:        record.ID.String(),
				Purpose:   record.Purpose,
				GrantedAt: record.GrantedAt,
				ExpiresAt: record.ExpiresAt,
				RevokedAt: record.RevokedAt,
			},
			Status: record.ComputeStatus(now),
		})
	}
	return &models.ListResponse{Consents: consents}
}

// Helper functions

func formatActionMessage(template string, count int) string {
	suffix := "s"
	if count == 1 {
		suffix = ""
	}
	return fmt.Sprintf(template+"%s", count, suffix)
}

// requireUserID retrieves the typed user ID from auth context.
// Returns a domain error suitable for HTTP response on failure.
func (h *Handler) requireUserID(ctx context.Context, requestID string) (id.UserID, error) {
	userID := auth.GetUserID(ctx)
	if userID.IsNil() {
		h.logger.ErrorContext(ctx, "userID missing from context despite auth middleware",
			"request_id", requestID)
		return id.UserID{}, dErrors.New(dErrors.CodeInternal, "authentication context error")
	}
	return userID, nil
}
