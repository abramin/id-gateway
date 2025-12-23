package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

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

// Handler handles consent-related endpoints.
type Handler struct {
	logger  *slog.Logger
	consent Service
	metrics *consentmetrics.Metrics
}

// New creates a new consent Handler.
func New(consent Service, logger *slog.Logger, metrics *consentmetrics.Metrics) *Handler {
	return &Handler{
		logger:  logger,
		consent: consent,
		metrics: metrics,
	}
}

// requireUserID extracts and validates the authenticated user ID from context.
// Returns a domain error suitable for HTTP response on failure.
func (h *Handler) requireUserID(ctx context.Context, requestID string) (id.UserID, error) {
	userIDStr := auth.GetUserID(ctx)
	if userIDStr == "" {
		h.logger.ErrorContext(ctx, "userID missing from context despite auth middleware",
			"request_id", requestID)
		return id.UserID{}, dErrors.New(dErrors.CodeInternal, "authentication context error")
	}
	userID, err := id.ParseUserID(userIDStr)
	if err != nil {
		h.logger.ErrorContext(ctx, "invalid userID in context",
			"request_id", requestID, "error", err)
		return id.UserID{}, dErrors.New(dErrors.CodeInternal, "authentication context error")
	}
	return userID, nil
}

// HandleGrantConsent grants consent for the authenticated user per PRD-002 FR-1.
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

	var grantReq models.GrantRequest
	if err := json.NewDecoder(r.Body).Decode(&grantReq); err != nil {
		h.logger.WarnContext(ctx, "failed to decode grant consent request",
			"request_id", requestID,
			"error", err,
		)
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid request body"))
		return
	}
	if err := prepareRequest(&grantReq); err != nil {
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

	httputil.WriteJSON(w, http.StatusOK, toGrantResponse(records, requesttime.Now(ctx)))
}

func (h *Handler) HandleRevokeConsent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)
	userID, err := h.requireUserID(ctx, requestID)
	if err != nil {
		httputil.WriteError(w, err)
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
	if err := prepareRequest(&revokeReq); err != nil {
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

	httputil.WriteJSON(w, http.StatusOK, toRevokeResponse(records, requesttime.Now(ctx)))
}

func (h *Handler) HandleRevokeAllConsents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)
	userID, err := h.requireUserID(ctx, requestID)
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

	httputil.WriteJSON(w, http.StatusOK, &models.RevokeResponse{
		Revoked: nil,
		Message: formatActionMessage("Consent revoked for %d purpose", count),
	})
}

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

func (h *Handler) HandleGetConsents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)
	userID, err := h.requireUserID(ctx, requestID)
	if err != nil {
		httputil.WriteError(w, err)
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

// prepareRequest sanitizes, normalizes, and validates a consent request.
// This replaces the reflection-based sanitize() with type-safe methods.
func prepareRequest(req models.ConsentRequest) error {
	req.Sanitize()
	req.Normalize()
	return req.Validate()
}
