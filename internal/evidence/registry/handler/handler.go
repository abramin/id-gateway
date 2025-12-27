package handler

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
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

// nationalIDPattern validates the national ID format: 6-20 alphanumeric characters
var nationalIDPattern = regexp.MustCompile(`^[A-Z0-9]{6,20}$`)

// RegistryService defines the interface for registry operations used by handlers
type RegistryService interface {
	Citizen(ctx context.Context, nationalID string) (*models.CitizenRecord, error)
	Sanctions(ctx context.Context, nationalID string) (*models.SanctionsRecord, error)
	Check(ctx context.Context, nationalID string) (*models.RegistryResult, error)
}

// Handler handles HTTP requests for registry operations.
type Handler struct {
	service     RegistryService
	consentPort ports.ConsentPort
	auditPort   ports.AuditPort
	logger      *slog.Logger
}

// New creates a new registry handler.
func New(service RegistryService, consentPort ports.ConsentPort, auditPort ports.AuditPort, logger *slog.Logger) *Handler {
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
}

// CitizenLookupRequest is the request body for citizen lookup.
type CitizenLookupRequest struct {
	NationalID string `json:"national_id"`
}

// Validate validates the citizen lookup request.
func (r *CitizenLookupRequest) Validate() error {
	if r.NationalID == "" {
		return dErrors.New(dErrors.CodeBadRequest, "national_id is required")
	}
	if !nationalIDPattern.MatchString(r.NationalID) {
		return dErrors.New(dErrors.CodeBadRequest, "national_id has invalid format: must be 6-20 alphanumeric characters")
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

	// Check consent for registry_check purpose
	if err := h.consentPort.RequireConsent(ctx, userID.String(), "registry_check"); err != nil {
		h.logger.ErrorContext(ctx, "consent check failed",
			"request_id", requestID,
			"user_id", userID,
			"error", err,
		)
		httputil.WriteError(w, err)
		return
	}

	// Perform citizen lookup
	record, err := h.service.Citizen(ctx, req.NationalID)
	if err != nil {
		h.logger.ErrorContext(ctx, "citizen lookup failed",
			"request_id", requestID,
			"user_id", userID,
			"national_id", req.NationalID,
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
