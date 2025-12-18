package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"credo/internal/consent/models"
	"credo/internal/platform/metrics"
	"credo/internal/platform/middleware"
	"credo/internal/transport/httputil"
	dErrors "credo/pkg/domain-errors"
	s "credo/pkg/string"
)

// Service defines the interface for consent operations.
// Returns domain objects, not HTTP response DTOs.
type Service interface {
	Grant(ctx context.Context, userID string, purposes []models.Purpose) ([]*models.Record, error)
	Revoke(ctx context.Context, userID string, purposes []models.Purpose) ([]*models.Record, error)
	RevokeAll(ctx context.Context, userID string) (int, error)
	DeleteAll(ctx context.Context, userID string) error
	List(ctx context.Context, userID string, filter *models.RecordFilter) ([]*models.Record, error)
}

// Handler handles consent-related endpoints.
type Handler struct {
	logger  *slog.Logger
	consent Service
	metrics *metrics.Metrics
}

// New creates a new consent Handler.
func New(consent Service, logger *slog.Logger, metrics *metrics.Metrics) *Handler {
	return &Handler{
		logger:  logger,
		consent: consent,
		metrics: metrics,
	}
}

// Register registers the consent routes with the chi router.
func (h *Handler) Register(r chi.Router) {
	r.Post("/auth/consent", h.handleGrantConsent)
	r.Post("/auth/consent/revoke", h.handleRevokeConsent)
	r.Post("/auth/consent/revoke-all", h.handleRevokeAllConsents)
	r.Delete("/auth/consent", h.handleDeleteAllConsents)
	r.Get("/auth/consent", h.handleGetConsents)
}

// handleGrantConsent grants consent for the authenticated user per PRD-002 FR-1.
func (h *Handler) handleGrantConsent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := time.Now()
	defer func() {
		if h.metrics != nil {
			h.metrics.ObserveConsentGrantLatency(time.Since(start).Seconds())
		}
	}()

	requestID := middleware.GetRequestID(ctx)
	userID := middleware.GetUserID(ctx)

	if userID == "" {
		h.logger.ErrorContext(ctx, "userID missing from context despite auth middleware",
			"request_id", requestID,
		)
		httputil.WriteError(w, dErrors.New(dErrors.CodeInternal, "authentication context error"))
		return
	}

	var grantReq models.GrantRequest
	if err := json.NewDecoder(r.Body).Decode(&grantReq); err != nil {
		h.logger.WarnContext(ctx, "failed to decode grant consent request",
			"request_id", requestID,
			"error", err,
		)
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid request body"))
		return
	}
	s.Sanitize(&grantReq)
	grantReq.Normalize()
	if err := grantReq.Validate(); err != nil {
		h.logger.WarnContext(ctx, "invalid grant consent request",
			"request_id", requestID,
			"error", err,
		)
		httputil.WriteError(w, mapValidationError(err))
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

	httputil.WriteJSON(w, http.StatusOK, toGrantResponse(records, time.Now()))
}

func (h *Handler) handleRevokeConsent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)
	userID := middleware.GetUserID(ctx)

	if userID == "" {
		h.logger.ErrorContext(ctx, "userID missing from context despite auth middleware",
			"request_id", requestID,
		)
		httputil.WriteError(w, dErrors.New(dErrors.CodeInternal, "authentication context error"))
		return
	}

	var revokeReq models.RevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&revokeReq); err != nil {
		h.logger.WarnContext(ctx, "failed to decode revoke consent request",
			"request_id", requestID,
			"error", err,
		)
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid request body"))
		return
	}
	s.Sanitize(&revokeReq)
	revokeReq.Normalize()
	if err := revokeReq.Validate(); err != nil {
		h.logger.WarnContext(ctx, "invalid revoke consent request",
			"request_id", requestID,
			"error", err,
		)
		httputil.WriteError(w, mapValidationError(err))
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

	httputil.WriteJSON(w, http.StatusOK, toRevokeResponse(records, time.Now()))
}

func (h *Handler) handleRevokeAllConsents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)
	userID := middleware.GetUserID(ctx)

	if userID == "" {
		h.logger.ErrorContext(ctx, "userID missing from context despite auth middleware",
			"request_id", requestID,
		)
		httputil.WriteError(w, dErrors.New(dErrors.CodeInternal, "authentication context error"))
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

	httputil.WriteJSON(w, http.StatusOK, &models.RevokeResponse{
		Revoked: nil,
		Message: formatActionMessage("Consent revoked for %d purpose", count),
	})
}

func (h *Handler) handleDeleteAllConsents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)
	userID := middleware.GetUserID(ctx)

	if userID == "" {
		h.logger.ErrorContext(ctx, "userID missing from context despite auth middleware",
			"request_id", requestID,
		)
		httputil.WriteError(w, dErrors.New(dErrors.CodeInternal, "authentication context error"))
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

func (h *Handler) handleGetConsents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)
	userID := middleware.GetUserID(ctx)

	if userID == "" {
		h.logger.ErrorContext(ctx, "userID missing from context despite auth middleware",
			"request_id", requestID,
		)
		httputil.WriteError(w, dErrors.New(dErrors.CodeInternal, "authentication context error"))
		return
	}

	// Parse and validate query parameters
	status := r.URL.Query().Get("status")
	purpose := r.URL.Query().Get("purpose")

	if status != "" && !isValidStatus(status) {
		httputil.WriteError(w, dErrors.New(dErrors.CodeValidation, "invalid status filter"))
		return
	}
	if purpose != "" && !models.Purpose(purpose).IsValid() {
		httputil.WriteError(w, dErrors.New(dErrors.CodeValidation, "invalid purpose filter"))
		return
	}

	records, err := h.consent.List(ctx, userID, &models.RecordFilter{
		Purpose: purpose,
		Status:  status,
	})
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to list consent",
			"request_id", requestID,
			"error", err,
		)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, toListResponse(records, time.Now()))
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
				ID:        record.ID,
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

func isValidStatus(status string) bool {
	return status == string(models.StatusActive) ||
		status == string(models.StatusExpired) ||
		status == string(models.StatusRevoked)
}

func formatActionMessage(template string, count int) string {
	suffix := "s"
	if count == 1 {
		suffix = ""
	}
	return fmt.Sprintf(template+"%s", count, suffix)
}

// mapValidationError converts validation errors to domain errors.
func mapValidationError(err error) error {
	return dErrors.New(dErrors.CodeValidation, err.Error())
}
