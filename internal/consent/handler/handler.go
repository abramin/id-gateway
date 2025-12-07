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
	dErrors "id-gateway/pkg/domain-errors"
	s "id-gateway/pkg/string"
	"id-gateway/pkg/validation"
)

// Service defines the interface for consent operations.
type Service interface {
	Grant(ctx context.Context, userID string, purposes []consentModel.ConsentPurpose) ([]*consentModel.ConsentRecord, error)
	Revoke(ctx context.Context, userID string, purpose consentModel.ConsentPurpose) error
	Require(ctx context.Context, userID string, purpose consentModel.ConsentPurpose) error
	List(ctx context.Context, userID string) ([]*consentModel.ConsentRecord, error)
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
	r.Get("/auth/consent", h.handleGetConsent)
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

	var grantReq consentModel.GrantConsentRequest
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

	response := &consentModel.ConsentActionResponse{
		Granted: formatConsentResponses(granted, time.Now()),
		Message: formatActionMessage("Consent granted for %d purposes", len(granted)),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
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

	var revokeReq consentModel.RevokeConsentRequest
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

	var revoked []*consentModel.ConsentRecord
	for _, purpose := range revokeReq.Purposes {
		if err := h.consent.Revoke(ctx, userID, purpose); err != nil {
			h.logger.ErrorContext(ctx, "failed to revoke consent",
				"request_id", requestID,
				"error", err,
			)
			shared.WriteError(w, err)
			return
		}
		revoked = append(revoked, &consentModel.ConsentRecord{Purpose: purpose, RevokedAt: ptrTime(time.Now())})
	}
	response := &consentModel.ConsentActionResponse{
		Granted: formatConsentResponses(revoked, time.Now()),
		Message: formatActionMessage("Consent revoked for %d purpose", len(revoked)),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

func (h *Handler) handleGetConsent(w http.ResponseWriter, r *http.Request) {
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

	statusFilter := r.URL.Query().Get("status")
	purposeFilter := r.URL.Query().Get("purpose")

	if statusFilter != "" && statusFilter != "active" && statusFilter != "expired" && statusFilter != "revoked" {
		shared.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid status filter"))
		return
	}

	var purpose consentModel.ConsentPurpose
	if purposeFilter != "" {
		purpose = consentModel.ConsentPurpose(purposeFilter)
		if !purpose.IsValid() {
			shared.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid purpose filter"))
			return
		}
	}

	consents, err := h.consent.List(ctx, userID)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to list consent",
			"request_id", requestID,
			"error", err,
		)
		shared.WriteError(w, err)
		return
	}

	now := time.Now()
	filtered := filterConsents(consents, purposeFilter, statusFilter, now)
	response := map[string]any{
		"consents": formatConsentResponses(filtered, now),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

func formatConsentResponses(records []*consentModel.ConsentRecord, now time.Time) []consentModel.ConsentGrant {
	var resp []consentModel.ConsentGrant
	for _, record := range records {
		resp = append(resp, consentModel.ConsentGrant{
			Purpose:   record.Purpose,
			GrantedAt: record.GrantedAt,
			ExpiresAt: record.ExpiresAt,
			Status:    record.Status(now),
		})
	}
	return resp
}

func filterConsents(records []*consentModel.ConsentRecord, purposeFilter, statusFilter string, now time.Time) []*consentModel.ConsentRecord {
	var filtered []*consentModel.ConsentRecord
	for _, record := range records {
		if purposeFilter != "" && string(record.Purpose) != purposeFilter {
			continue
		}
		if statusFilter != "" && record.Status(now) != statusFilter {
			continue
		}
		filtered = append(filtered, record)
	}
	return filtered
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
