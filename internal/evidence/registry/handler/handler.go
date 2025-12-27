package handler

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"credo/internal/evidence/registry/models"
	"credo/internal/evidence/registry/ports"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	"credo/pkg/platform/httputil"
	auth "credo/pkg/platform/middleware/auth"
	"credo/pkg/platform/middleware/request"
)

// RegistryService defines the interface for registry operations used by handlers.
// Methods accept type-safe NationalID to enforce validation at parse time.
type RegistryService interface {
	Citizen(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*models.CitizenRecord, error)
	Sanctions(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*models.SanctionsRecord, error)
	Check(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*models.RegistryResult, error)
}

// AuditPublisher emits audit events for security-relevant operations.
type AuditPublisher interface {
	Emit(ctx context.Context, event audit.Event) error
}

// Handler handles HTTP requests for registry operations.
type Handler struct {
	service     RegistryService
	consentPort ports.ConsentPort
	auditPort   AuditPublisher
	logger      *slog.Logger
}

// New creates a new registry handler.
func New(service RegistryService, consentPort ports.ConsentPort, auditPort AuditPublisher, logger *slog.Logger) *Handler {
	return &Handler{
		service:     service,
		consentPort: consentPort,
		auditPort:   auditPort,
		logger:      logger,
	}
}

// Register mounts the handler routes on the given router.
func (h *Handler) Register(r chi.Router) {
	r.Post("/registry/citizen", h.HandleCitizenLookup)
	r.Post("/registry/sanctions", h.HandleSanctionsLookup)
}

// CitizenLookupRequest is the request body for citizen lookup.
type CitizenLookupRequest struct {
	NationalID string `json:"national_id"`
}

// Validate validates the citizen lookup request using the NationalID domain primitive.
func (r *CitizenLookupRequest) Validate() error {
	_, err := id.ParseNationalID(r.NationalID)
	if err != nil {
		return dErrors.New(dErrors.CodeBadRequest, err.Error())
	}
	return nil
}

// CitizenLookupResponse is the response body for citizen lookup.
type CitizenLookupResponse struct {
	NationalID  string `json:"national_id,omitempty"`
	FullName    string `json:"full_name,omitempty"`
	DateOfBirth string `json:"date_of_birth,omitempty"`
	Address     string `json:"address,omitempty"`
	Valid       bool   `json:"valid"`
	CheckedAt   string `json:"checked_at"`
}

// SanctionsCheckRequest is the request body for sanctions lookup.
type SanctionsCheckRequest struct {
	NationalID string `json:"national_id"`
}

// Validate validates the sanctions check request using the NationalID domain primitive.
func (r *SanctionsCheckRequest) Validate() error {
	_, err := id.ParseNationalID(r.NationalID)
	if err != nil {
		return dErrors.New(dErrors.CodeBadRequest, err.Error())
	}
	return nil
}

// SanctionsCheckResponse is the response body for sanctions lookup.
type SanctionsCheckResponse struct {
	NationalID string `json:"national_id"`
	Listed     bool   `json:"listed"`
	Source     string `json:"source"`
	CheckedAt  string `json:"checked_at"`
}

// HandleCitizenLookup handles POST /registry/citizen requests.
func (h *Handler) HandleCitizenLookup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	// Extract authenticated user ID
	userID, err := h.requireUserID(ctx, requestID)
	if err != nil {
		httputil.WriteError(w, err)
		return
	}

	// Decode and validate request
	req, ok := httputil.DecodeAndPrepare[CitizenLookupRequest](w, r, h.logger, ctx, requestID)
	if !ok {
		return
	}

	// Parse NationalID into domain primitive (validation already done in Validate)
	nationalID, _ := id.ParseNationalID(req.NationalID)

	// Perform citizen lookup (consent check is atomic within service)
	record, err := h.service.Citizen(ctx, userID, nationalID)
	if err != nil {
		h.logger.ErrorContext(ctx, "citizen lookup failed",
			"request_id", requestID,
			"user_id", userID,
			"national_id_suffix", redactNationalID(nationalID),
			"error", err,
		)
		httputil.WriteError(w, err)
		return
	}

	// Emit audit event
	h.emitAudit(ctx, audit.Event{
		Action:    "registry_citizen_checked",
		Purpose:   "registry_check",
		UserID:    userID,
		Decision:  "checked",
		Reason:    "user_initiated",
		RequestID: requestID,
	})

	// Map to response
	response := CitizenLookupResponse{
		NationalID:  record.NationalID,
		FullName:    record.FullName,
		DateOfBirth: record.DateOfBirth,
		Address:     record.Address,
		Valid:       record.Valid,
		CheckedAt:   record.CheckedAt.Format(time.RFC3339),
	}

	httputil.WriteJSON(w, http.StatusOK, response)
}

// HandleSanctionsLookup handles POST /registry/sanctions requests.
func (h *Handler) HandleSanctionsLookup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	// Extract authenticated user ID
	userID, err := h.requireUserID(ctx, requestID)
	if err != nil {
		httputil.WriteError(w, err)
		return
	}

	// Decode and validate request
	req, ok := httputil.DecodeAndPrepare[SanctionsCheckRequest](w, r, h.logger, ctx, requestID)
	if !ok {
		return
	}

	// Parse NationalID into domain primitive (validation already done in Validate)
	nationalID, _ := id.ParseNationalID(req.NationalID)

	// Perform sanctions lookup (consent check is atomic within service)
	record, err := h.service.Sanctions(ctx, userID, nationalID)
	if err != nil {
		h.logger.ErrorContext(ctx, "sanctions lookup failed",
			"request_id", requestID,
			"user_id", userID,
			"national_id_suffix", redactNationalID(nationalID),
			"error", err,
		)
		httputil.WriteError(w, err)
		return
	}

	// Emit audit event with fail-closed semantics for listed sanctions
	if err := h.auditSanctionsCheck(ctx, userID, nationalID, record.Listed, requestID); err != nil {
		httputil.WriteError(w, err)
		return
	}

	// Map to response
	response := SanctionsCheckResponse{
		NationalID: record.NationalID,
		Listed:     record.Listed,
		Source:     record.Source,
		CheckedAt:  record.CheckedAt.Format(time.RFC3339),
	}

	httputil.WriteJSON(w, http.StatusOK, response)
}

// requireUserID extracts and validates the authenticated user ID from context.
func (h *Handler) requireUserID(ctx context.Context, requestID string) (id.UserID, error) {
	userID := auth.GetUserID(ctx)
	if userID.IsNil() {
		h.logger.ErrorContext(ctx, "userID missing from context despite auth middleware",
			"request_id", requestID)
		return id.UserID{}, dErrors.New(dErrors.CodeUnauthorized, "authentication required")
	}
	return userID, nil
}

// emitAudit publishes an audit event. Failures are logged but don't fail the operation.
func (h *Handler) emitAudit(ctx context.Context, event audit.Event) {
	if h.auditPort == nil {
		return
	}
	if err := h.auditPort.Emit(ctx, event); err != nil {
		h.logger.ErrorContext(ctx, "failed to emit audit event",
			"error", err,
			"action", event.Action,
			"user_id", event.UserID,
		)
	}
}

// emitCriticalAudit publishes an audit event that MUST succeed.
// Returns an error if the audit fails, allowing callers to fail-close.
// Use this for security-critical events like sanctions hits.
func (h *Handler) emitCriticalAudit(ctx context.Context, event audit.Event) error {
	if h.auditPort == nil {
		return dErrors.New(dErrors.CodeInternal, "audit system unavailable")
	}
	return h.auditPort.Emit(ctx, event)
}

// auditSanctionsCheck emits an audit event for a sanctions check with fail-closed semantics.
// For listed sanctions, the audit MUST succeed before the response is returned.
// For non-listed results, audit failures are logged but don't block the response.
func (h *Handler) auditSanctionsCheck(ctx context.Context, userID id.UserID, nationalID id.NationalID, listed bool, requestID string) error {
	decision := "not_listed"
	if listed {
		decision = "listed"
	}

	event := audit.Event{
		Action:    "registry_sanctions_checked",
		Purpose:   "registry_check",
		UserID:    userID,
		Decision:  decision,
		Reason:    "user_initiated",
		RequestID: requestID,
	}

	if listed {
		if err := h.emitCriticalAudit(ctx, event); err != nil {
			h.logger.ErrorContext(ctx, "CRITICAL: audit failed for listed sanctions - blocking response",
				"request_id", requestID,
				"user_id", userID,
				"national_id_suffix", redactNationalID(nationalID),
				"error", err,
			)
			return dErrors.New(dErrors.CodeInternal, "unable to complete sanctions check")
		}
		return nil
	}

	h.emitAudit(ctx, event)
	return nil
}

// redactNationalID returns a redacted version of the NationalID safe for logging.
// Shows only the last 4 characters to allow correlation without exposing full PII.
func redactNationalID(nid id.NationalID) string {
	s := nid.String()
	if len(s) <= 4 {
		return "****"
	}
	return "****" + s[len(s)-4:]
}
