package handler

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"credo/internal/evidence/vc/models"
	vcservice "credo/internal/evidence/vc/service"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/httputil"
	"credo/pkg/requestcontext"
)

// Service defines the VC issuance operations used by the handler.
type Service interface {
	Issue(ctx context.Context, req models.IssueRequest) (*models.CredentialRecord, error)
	Verify(ctx context.Context, credentialID models.CredentialID) (*models.VerifyResult, error)
}

// Handler wires VC endpoints to the VC service.
type Handler struct {
	service Service
	logger  *slog.Logger
}

// New constructs a VC handler with its dependencies.
func New(service Service, logger *slog.Logger) *Handler {
	return &Handler{service: service, logger: logger}
}

// Register mounts VC endpoints on the router.
func (h *Handler) Register(r chi.Router) {
	r.Post("/vc/issue", h.HandleIssue)
	r.Post("/vc/verify", h.HandleVerify)
}

// IssueRequest is the request body for credential issuance.
type IssueRequest struct {
	Type       string `json:"type"`
	NationalID string `json:"national_id"`

	parsedType       models.CredentialType
	parsedNationalID id.NationalID
}

// Validate validates and parses the issuance request.
func (r *IssueRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}

	// Phase 1: Size validation (fail fast on oversized input)
	if len(r.NationalID) > 20 {
		return dErrors.New(dErrors.CodeValidation, "national_id must be 6-20 characters")
	}

	// Phase 2: Required fields
	if r.Type == "" {
		return dErrors.New(dErrors.CodeValidation, "type is required")
	}
	if r.NationalID == "" {
		return dErrors.New(dErrors.CodeValidation, "national_id is required")
	}

	// Phase 3: Syntax and lexical validation
	parsedType, err := models.ParseCredentialType(r.Type)
	if err != nil {
		return dErrors.New(dErrors.CodeBadRequest, err.Error())
	}
	parsedNationalID, err := id.ParseNationalID(r.NationalID)
	if err != nil {
		return dErrors.New(dErrors.CodeBadRequest, err.Error())
	}

	r.parsedType = parsedType
	r.parsedNationalID = parsedNationalID
	return nil
}

// ParsedType returns the validated credential type.
func (r *IssueRequest) ParsedType() models.CredentialType {
	return r.parsedType
}

// ParsedNationalID returns the validated national ID.
func (r *IssueRequest) ParsedNationalID() id.NationalID {
	return r.parsedNationalID
}

// IssueResponse is the response body for credential issuance.
type IssueResponse struct {
	CredentialID string        `json:"credential_id"`
	Type         string        `json:"type"`
	Subject      string        `json:"subject"`
	Issuer       string        `json:"issuer"`
	IssuedAt     time.Time     `json:"issued_at"`
	Claims       models.Claims `json:"claims"`
}

// VerifyRequest is the request body for credential verification.
type VerifyRequest struct {
	CredentialID string `json:"credential_id"`

	parsedCredentialID models.CredentialID
}

// Validate validates and parses the verification request.
func (r *VerifyRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}

	// Phase 1: Size validation (fail fast on oversized input)
	if len(r.CredentialID) > 64 {
		return dErrors.New(dErrors.CodeValidation, "credential_id is too long")
	}

	// Phase 2: Required fields
	if r.CredentialID == "" {
		return dErrors.New(dErrors.CodeValidation, "credential_id is required")
	}

	// Phase 3: Syntax and lexical validation
	parsedID, err := models.ParseCredentialID(r.CredentialID)
	if err != nil {
		return dErrors.New(dErrors.CodeBadRequest, err.Error())
	}

	r.parsedCredentialID = parsedID
	return nil
}

// ParsedCredentialID returns the validated credential ID.
func (r *VerifyRequest) ParsedCredentialID() models.CredentialID {
	return r.parsedCredentialID
}

// VerifyResponse is the response body for credential verification.
type VerifyResponse struct {
	Valid        bool          `json:"valid"`
	CredentialID string        `json:"credential_id,omitempty"`
	Type         string        `json:"type,omitempty"`
	Subject      string        `json:"subject,omitempty"`
	IssuedAt     time.Time     `json:"issued_at,omitempty"`
	Claims       models.Claims `json:"claims,omitempty"`
	Reason       string        `json:"reason,omitempty"`
}

// HandleIssue handles POST /vc/issue requests.
func (h *Handler) HandleIssue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := requestcontext.RequestID(ctx)

	userID := requestcontext.UserID(ctx)
	if userID.IsNil() {
		httputil.WriteError(w, dErrors.New(dErrors.CodeUnauthorized, "authentication required"))
		return
	}

	req, ok := httputil.DecodeAndPrepare[IssueRequest](w, r, h.logger, ctx, requestID)
	if !ok {
		return
	}

	credential, err := h.service.Issue(ctx, models.IssueRequest{
		UserID:     userID,
		Type:       req.ParsedType(),
		NationalID: req.ParsedNationalID(),
	})
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to issue credential",
			"request_id", requestID,
			"user_id", userID,
			"error", err,
		)
		httputil.WriteError(w, err)
		return
	}

	response := IssueResponse{
		CredentialID: credential.ID.String(),
		Type:         string(credential.Type),
		Subject:      credential.Subject.String(),
		Issuer:       credential.Issuer,
		IssuedAt:     credential.IssuedAt.UTC(),
		Claims:       credential.Claims,
	}

	httputil.WriteJSON(w, http.StatusOK, response)
}

// HandleVerify handles POST /vc/verify requests.
func (h *Handler) HandleVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := requestcontext.RequestID(ctx)

	userID := requestcontext.UserID(ctx)
	if userID.IsNil() {
		httputil.WriteError(w, dErrors.New(dErrors.CodeUnauthorized, "authentication required"))
		return
	}

	req, ok := httputil.DecodeAndPrepare[VerifyRequest](w, r, h.logger, ctx, requestID)
	if !ok {
		return
	}

	result, err := h.service.Verify(ctx, req.ParsedCredentialID())
	if err != nil {
		if dErrors.HasCode(err, dErrors.CodeNotFound) {
			httputil.WriteJSON(w, http.StatusNotFound, VerifyResponse{
				Valid:  false,
				Reason: "credential_not_found",
			})
			return
		}

		h.logger.ErrorContext(ctx, "failed to verify credential",
			"request_id", requestID,
			"user_id", userID,
			"credential_id", req.CredentialID,
			"error", err,
		)
		httputil.WriteError(w, err)
		return
	}

	response := VerifyResponse{
		Valid:        result.Valid,
		CredentialID: result.Credential.ID.String(),
		Type:         string(result.Credential.Type),
		Subject:      result.Credential.Subject.String(),
		IssuedAt:     result.Credential.IssuedAt.UTC(),
		Claims:       result.Credential.Claims,
	}

	httputil.WriteJSON(w, http.StatusOK, response)
}

var _ Service = (*vcservice.Service)(nil)
