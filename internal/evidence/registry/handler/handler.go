package handler

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"credo/internal/evidence/registry/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	"credo/pkg/platform/audit/publishers/ops"
	"credo/pkg/platform/httputil"
	"credo/pkg/requestcontext"
)

// Tracer for distributed tracing of handler operations.
var handlerTracer = otel.Tracer("credo/registry/handler")

// RegistryService defines the interface for registry operations used by handlers.
// Methods accept type-safe NationalID to enforce validation at parse time.
type RegistryService interface {
	Citizen(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*models.CitizenRecord, error)
	Sanctions(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*models.SanctionsRecord, error)
	Check(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*models.RegistryResult, error)
}

// Handler handles HTTP requests for registry operations.
type Handler struct {
	service    RegistryService
	opsTracker *ops.Publisher
	logger     *slog.Logger
}

// New creates a new registry handler.
func New(service RegistryService, opsTracker *ops.Publisher, logger *slog.Logger) *Handler {
	return &Handler{
		service:    service,
		opsTracker: opsTracker,
		logger:     logger,
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

	// parsedNationalID holds the validated domain primitive after Validate() succeeds.
	// This avoids double-parsing: Validate() parses once, handler uses the result.
	parsedNationalID id.NationalID
}

// Validate validates the citizen lookup request and parses NationalID into a domain primitive.
// After validation succeeds, use ParsedNationalID() to access the domain type.
func (r *CitizenLookupRequest) Validate() error {
	parsed, err := id.ParseNationalID(r.NationalID)
	if err != nil {
		return dErrors.New(dErrors.CodeBadRequest, err.Error())
	}
	r.parsedNationalID = parsed
	return nil
}

// ParsedNationalID returns the validated NationalID domain primitive.
// Must only be called after Validate() succeeds.
func (r *CitizenLookupRequest) ParsedNationalID() id.NationalID {
	return r.parsedNationalID
}

// CitizenLookupResponse is the response body for citizen lookup.
type CitizenLookupResponse struct {
	NationalID  string `json:"national_id,omitempty"`
	FullName    string `json:"full_name,omitempty"`
	DateOfBirth string `json:"date_of_birth,omitempty"`
	Address     string `json:"address,omitempty"`
	Valid       bool   `json:"valid"`
	Source      string `json:"source"`
	CheckedAt   string `json:"checked_at"`
}

// SanctionsCheckRequest is the request body for sanctions lookup.
type SanctionsCheckRequest struct {
	NationalID string `json:"national_id"`

	// parsedNationalID holds the validated domain primitive after Validate() succeeds.
	parsedNationalID id.NationalID
}

// Validate validates the sanctions check request and parses NationalID into a domain primitive.
// After validation succeeds, use ParsedNationalID() to access the domain type.
func (r *SanctionsCheckRequest) Validate() error {
	parsed, err := id.ParseNationalID(r.NationalID)
	if err != nil {
		return dErrors.New(dErrors.CodeBadRequest, err.Error())
	}
	r.parsedNationalID = parsed
	return nil
}

// ParsedNationalID returns the validated NationalID domain primitive.
// Must only be called after Validate() succeeds.
func (r *SanctionsCheckRequest) ParsedNationalID() id.NationalID {
	return r.parsedNationalID
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
	requestID := requestcontext.RequestID(ctx)

	// Extract authenticated user ID
	userID, err := httputil.RequireUserID(ctx, h.logger, requestID)
	if err != nil {
		httputil.WriteError(w, err)
		return
	}

	// Decode and validate request
	req, ok := httputil.DecodeAndPrepare[CitizenLookupRequest](w, r, h.logger, ctx, requestID)
	if !ok {
		return
	}

	// Use the already-parsed domain primitive from validation
	nationalID := req.ParsedNationalID()

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

	// Emit operational audit event (fire-and-forget with sampling)
	h.emitAudit(ctx, audit.OpsEvent{
		Action:    "registry_citizen_checked",
		Subject:   userID.String(),
		RequestID: requestID,
	})

	// Map to response
	response := CitizenLookupResponse{
		NationalID:  record.NationalID,
		FullName:    record.FullName,
		DateOfBirth: record.DateOfBirth,
		Address:     record.Address,
		Valid:       record.Valid,
		Source:      record.Source,
		CheckedAt:   record.CheckedAt.Format(time.RFC3339),
	}

	httputil.WriteJSON(w, http.StatusOK, response)
}

// HandleSanctionsLookup handles POST /registry/sanctions requests.
func (h *Handler) HandleSanctionsLookup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := requestcontext.RequestID(ctx)

	// Extract authenticated user ID
	userID, err := httputil.RequireUserID(ctx, h.logger, requestID)
	if err != nil {
		httputil.WriteError(w, err)
		return
	}

	// Decode and validate request
	req, ok := httputil.DecodeAndPrepare[SanctionsCheckRequest](w, r, h.logger, ctx, requestID)
	if !ok {
		return
	}

	// Use the already-parsed domain primitive from validation
	nationalID := req.ParsedNationalID()

	// Perform sanctions lookup (consent check and audit are atomic within service)
	// The service implements fail-closed audit semantics for listed sanctions.
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

	// Map to response
	response := SanctionsCheckResponse{
		NationalID: record.NationalID,
		Listed:     record.Listed,
		Source:     record.Source,
		CheckedAt:  record.CheckedAt.Format(time.RFC3339),
	}

	httputil.WriteJSON(w, http.StatusOK, response)
}

// emitAudit publishes an operational audit event using fire-and-forget semantics.
// When a tracer is configured, emits an audit.emitted span event after tracking.
func (h *Handler) emitAudit(ctx context.Context, event audit.OpsEvent) {
	if h.opsTracker == nil {
		return
	}
	h.opsTracker.Track(event)
	// Emit span event for audit trail correlation
	h.emitAuditSpanEvent(ctx, event.Action)
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

// emitAuditSpanEvent adds an audit.emitted span event to the current trace.
// This correlates audit logs with distributed traces for compliance analysis.
func (h *Handler) emitAuditSpanEvent(ctx context.Context, action string) {
	// Start a minimal span that ends immediately after adding the event
	_, span := handlerTracer.Start(ctx, "audit.publish",
		trace.WithAttributes(
			attribute.String("audit.action", action),
		),
	)
	span.AddEvent("audit.emitted",
		trace.WithAttributes(
			attribute.String("audit.action", action),
		),
	)
	span.End()
}
