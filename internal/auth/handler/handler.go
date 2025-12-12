package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"

	"credo/internal/auth/models"
	"credo/internal/platform/middleware"
	"credo/internal/transport/http/shared"
	respond "credo/internal/transport/http/shared/json"
	dErrors "credo/pkg/domain-errors"
	s "credo/pkg/string"
	"credo/pkg/validation"
)

// Service defines the interface for authentication operations.
type Service interface {
	Authorize(ctx context.Context, req *models.AuthorizationRequest) (*models.AuthorizationResult, error)
	Token(ctx context.Context, req *models.TokenRequest) (*models.TokenResult, error)
	UserInfo(ctx context.Context, sessionID string) (*models.UserInfoResult, error)
}

// Handler handles authentication endpoints including authorize, token, and userinfo.
// Implements the OIDC-lite flow described in PRD-001.
type Handler struct {
	regulatedMode bool
	auth          Service
	logger        *slog.Logger
}

// New creates a new auth Handler with the given service and logger.
func New(auth Service, logger *slog.Logger, regulatedMode bool) *Handler {
	return &Handler{
		regulatedMode: regulatedMode,
		auth:          auth,
		logger:        logger,
	}
}

// Register registers the auth routes with the chi router.
// Note: Authentication middleware should be applied by the parent router to protected routes.
func (h *Handler) Register(r chi.Router) {
	r.Post("/auth/authorize", h.HandleAuthorize)
	r.Post("/auth/token", h.HandleToken)
	r.Get("/auth/userinfo", h.HandleUserInfo)
}

// HandleAuthorize implements POST /auth/authorize per PRD-001 FR-1.
// Initiates an authentication session for a user by email.
// If the user doesn't exist, creates them automatically.
//
// Input: { "email": "user@example.com", "client_id": "demo-client", "scopes": [...], "redirect_uri": "...", "state": "..." }
// Output: { "code": "authz_...", "redirect_uri": "https://..." }
func (h *Handler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)

	var req *models.AuthorizationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.WarnContext(ctx, "failed to decode authorize request",
			"error", err,
			"request_id", requestID,
		)
		shared.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "Invalid JSON in request body"))
		return
	}

	// validate redirect_uri uses https
	parsedURI, err := url.Parse(req.RedirectURI)
	if err != nil || parsedURI.Scheme != "https" {
		h.logger.WarnContext(ctx, "insecure redirect_uri in authorize request",
			"redirect_uri", req.RedirectURI,
			"request_id", requestID,
		)
		shared.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "redirect_uri must use https scheme"))
		return
	}

	s.Sanitize(req)
	// default to "openid" scope if none provided
	if len(req.Scopes) == 0 {
		req.Scopes = []string{models.ScopeOpenID.String()}
	}
	if err := validation.Validate(req); err != nil {
		h.logger.WarnContext(ctx, "invalid authorize request",
			"error", err,
			"request_id", requestID,
		)
		shared.WriteError(w, err)
		return
	}

	res, err := h.auth.Authorize(ctx, req)
	if err != nil {
		h.logger.ErrorContext(ctx, "authorize failed",
			"error", err,
			"request_id", requestID,
			"client_id", req.ClientID,
		)
		shared.WriteError(w, err)
		return
	}

	h.logger.InfoContext(ctx, "authorize successful",
		"request_id", requestID,
		"client_id", req.ClientID,
	)

	respond.WriteJSON(w, http.StatusOK, res)
}

// HandleToken exchanges authorization code for tokens
func (h *Handler) HandleToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)

	var req models.TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.WarnContext(ctx, "failed to decode token request",
			"error", err,
			"request_id", requestID,
		)
		shared.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "Invalid JSON in request body"))
		return
	}
	s.Sanitize(&req)
	if err := validation.Validate(&req); err != nil {
		h.logger.WarnContext(ctx, "invalid token request",
			"error", err,
			"request_id", requestID,
		)
		shared.WriteError(w, err)
		return
	}

	res, err := h.auth.Token(ctx, &req)
	if err != nil {
		h.logger.ErrorContext(ctx, "token exchange failed",
			"error", err,
			"request_id", requestID,
			"client_id", req.ClientID,
		)
		shared.WriteError(w, err)
		return
	}

	h.logger.InfoContext(ctx, "token exchange successful",
		"request_id", requestID,
		"client_id", req.ClientID,
	)

	respond.WriteJSON(w, http.StatusOK, res)
}

// HandleUserInfo returns authenticated user information
func (h *Handler) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)
	sessionIDStr := middleware.GetSessionID(ctx)

	res, err := h.auth.UserInfo(ctx, sessionIDStr)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to get user info",
			"error", err,
			"request_id", requestID,
			"session_id", sessionIDStr,
		)
		shared.WriteError(w, err)
		return
	}

	h.logger.InfoContext(ctx, "user info retrieved successfully",
		"request_id", requestID,
		"session_id", sessionIDStr,
	)

	respond.WriteJSON(w, http.StatusOK, res)
}
