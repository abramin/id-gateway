package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	consentModel "id-gateway/internal/consent/models"
	"id-gateway/internal/platform/metrics"
	"id-gateway/internal/platform/middleware"
	"id-gateway/internal/transport/http/shared"
	respond "id-gateway/internal/transport/http/shared/json"
	dErrors "id-gateway/pkg/domain-errors"
	s "id-gateway/pkg/string"
	"id-gateway/pkg/validation"
)

// Service defines the interface for consent operations.
type Service interface {
	Grant(ctx context.Context, userID string, purposes []consentModel.Purpose) ([]*consentModel.Record, error)
	Revoke(ctx context.Context, userID string, purposes []consentModel.Purpose) ([]*consentModel.Record, error)
	List(ctx context.Context, userID string, filter *consentModel.RecordFilter) ([]*consentModel.RecordWithStatus, error)
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
	r.Get("/auth/consent", h.handleGetConsents)
}

// handleGrantConsent grants consent for the authenticated user per PRD-002 FR-1.
func (h *Handler) handleGrantConsent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)
	userID := middleware.GetUserID(ctx)

	if userID == "" {
		h.logger.ErrorContext(ctx, "userID missing from context despite auth middleware",
			"request_id", requestID,
		)
		shared.WriteError(w, dErrors.New(dErrors.CodeInternal, "authentication context error"))
		return
	}

	var grantReq consentModel.GrantRequest
	if err := json.NewDecoder(r.Body).Decode(&grantReq); err != nil {
		h.logger.WarnContext(ctx, "failed to decode grant consent request",
			"request_id", requestID,
			"error", err,
		)
		shared.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid request body"))
		return
	}
	s.Sanitize(&grantReq)
	if err := validation.Validate(&grantReq); err != nil {
		h.logger.WarnContext(ctx, "invalid grant consent request",
			"request_id", requestID,
			"error", err,
		)
		shared.WriteError(w, err)
		return
	}

	granted, err := h.consent.Grant(ctx, userID, grantReq.Purposes)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to grant consent",
			"request_id", requestID,
			"error", err,
		)
		shared.WriteError(w, err)
		return
	}

	res := &consentModel.ActionResponse{
		Granted: formatConsentResponses(granted, time.Now()),
		Message: formatActionMessage("Consent granted for %d purpose", len(granted)),
	}

	respond.WriteJSON(w, http.StatusOK, res)
}

func (h *Handler) handleRevokeConsent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)
	userID := middleware.GetUserID(ctx)

	if userID == "" {
		h.logger.ErrorContext(ctx, "userID missing from context despite auth middleware",
			"request_id", requestID,
		)
		shared.WriteError(w, dErrors.New(dErrors.CodeInternal, "authentication context error"))
		return
	}

	var revokeReq consentModel.RevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&revokeReq); err != nil {
		h.logger.WarnContext(ctx, "failed to decode revoke consent request",
			"request_id", requestID,
			"error", err,
		)
		shared.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid request body"))
		return
	}
	s.Sanitize(&revokeReq)
	if err := validation.Validate(&revokeReq); err != nil {
		h.logger.WarnContext(ctx, "invalid revoke consent request",
			"request_id", requestID,
			"error", err,
		)
		shared.WriteError(w, err)
		return
	}

	revoked, err := h.consent.Revoke(ctx, userID, revokeReq.Purposes)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to revoke consent",
			"request_id", requestID,
			"error", err,
		)
		shared.WriteError(w, err)
		return
	}

	res := &consentModel.ActionResponse{
		Granted: formatConsentResponses(revoked, time.Now()),
		Message: formatActionMessage("Consent revoked for %d purpose", len(revoked)),
	}

	respond.WriteJSON(w, http.StatusOK, res)
}

func (h *Handler) handleGetConsents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)
	userID := middleware.GetUserID(ctx)

	if userID == "" {
		h.logger.ErrorContext(ctx, "userID missing from context despite auth middleware",
			"request_id", requestID,
		)
		shared.WriteError(w, dErrors.New(dErrors.CodeInternal, "authentication context error"))
		return
	}

	// TODO: consider using DTO here
	statusFilter := r.URL.Query().Get("status")
	purposeFilter := r.URL.Query().Get("purpose")

	if statusFilter != "" && statusFilter != "active" && statusFilter != "expired" && statusFilter != "revoked" {
		shared.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid status filter"))
		return
	}

	res, err := h.consent.List(ctx, userID, &consentModel.RecordFilter{
		Purpose: purposeFilter,
		Status:  statusFilter,
	})
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to list consent",
			"request_id", requestID,
			"error", err,
		)
		shared.WriteError(w, err)
		return
	}

	respond.WriteJSON(w, http.StatusOK, consentModel.RecordsResponse{
		Records: res,
	})
}

// TODO: move to models or service package
func formatConsentResponses(records []*consentModel.Record, now time.Time) []consentModel.Grant {
	var resp []consentModel.Grant
	for _, record := range records {
		resp = append(resp, consentModel.Grant{
			Purpose:   record.Purpose,
			GrantedAt: record.GrantedAt,
			ExpiresAt: record.ExpiresAt,
			Status:    record.ComputeStatus(now),
		})
	}
	return resp
}

func ptrTime(t time.Time) *time.Time {
	return &t
}

func formatActionMessage(template string, count int) string {
	return fmt.Sprintf(template+"%s", count, pluralSuffix(count))
}

func pluralSuffix(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}
