package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"credo/internal/auth/models"
	"credo/internal/platform/middleware"
	httpError "credo/internal/transport/http/error"
	respond "credo/internal/transport/http/json"
	dErrors "credo/pkg/domain-errors"
	s "credo/pkg/string"
	"credo/pkg/validation"
)

// Service defines the interface for authentication operations.
type Service interface {
	Authorize(ctx context.Context, req *models.AuthorizationRequest) (*models.AuthorizationResult, error)
	Token(ctx context.Context, req *models.TokenRequest) (*models.TokenResult, error)
	UserInfo(ctx context.Context, sessionID string) (*models.UserInfoResult, error)
	DeleteUser(ctx context.Context, userID uuid.UUID) error
}

// Handler handles authentication endpoints including authorize, token, and userinfo.
// Implements the OIDC-lite flow described in PRD-001.
type Handler struct {
	auth             Service
	logger           *slog.Logger
	deviceCookieName string
	deviceCookieAge  int
}

// New creates a new auth Handler with the given service and logger.
func New(auth Service, logger *slog.Logger, deviceCookieName string, deviceCookieMaxAge int) *Handler {
	if deviceCookieName == "" {
		deviceCookieName = "__Secure-Device-ID"
	}
	if deviceCookieMaxAge <= 0 {
		deviceCookieMaxAge = 31536000
	}

	return &Handler{
		auth:             auth,
		logger:           logger,
		deviceCookieName: deviceCookieName,
		deviceCookieAge:  deviceCookieMaxAge,
	}
}

// Register registers the auth routes with the chi router.
// Note: Authentication middleware should be applied by the parent router to protected routes.
func (h *Handler) Register(r chi.Router) {
	r.Post("/auth/authorize", h.HandleAuthorize)
	r.Post("/auth/token", h.HandleToken)
	r.Get("/auth/userinfo", h.HandleUserInfo)
}

func (h *Handler) RegisterAdmin(r chi.Router) {
	r.Delete("/admin/auth/users/{user_id}", h.HandleAdminDeleteUser)
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
		httpError.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "Invalid JSON in request body"))
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
		httpError.WriteError(w, err)
		return
	}

	// Extract device ID cookie (if present) for device binding.
	if cookie, err := r.Cookie(h.deviceCookieName); err == nil && cookie != nil {
		ctx = middleware.WithDeviceID(ctx, cookie.Value)
	}

	res, err := h.auth.Authorize(ctx, req)
	if err != nil {
		h.logger.ErrorContext(ctx, "authorize failed",
			"error", err,
			"request_id", requestID,
			"client_id", req.ClientID,
		)
		httpError.WriteError(w, err)
		return
	}

	h.logger.InfoContext(ctx, "authorize successful",
		"request_id", requestID,
		"client_id", req.ClientID,
	)

	// Set device ID cookie (Phase 1: soft launch — generate cookie, no enforcement).
	if res.DeviceID != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     h.deviceCookieName,
			Value:    res.DeviceID,
			Path:     "/",
			MaxAge:   h.deviceCookieAge,
			HttpOnly: true,
			Secure:   isHTTPS(r),
			SameSite: http.SameSiteStrictMode,
		})
	}

	respond.WriteJSON(w, http.StatusOK, res)
}

// HandleToken exchanges authorization code for tokens
func (h *Handler) HandleToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)

	// Extract device ID from cookie for device binding validation.
	if cookie, err := r.Cookie(h.deviceCookieName); err == nil && cookie != nil {
		ctx = middleware.WithDeviceID(ctx, cookie.Value)
	}

	var req models.TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.WarnContext(ctx, "failed to decode token request",
			"error", err,
			"request_id", requestID,
		)
		httpError.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "Invalid JSON in request body"))
		return
	}
	s.Sanitize(&req)
	if err := validation.Validate(&req); err != nil {
		h.logger.WarnContext(ctx, "invalid token request",
			"error", err,
			"request_id", requestID,
		)
		httpError.WriteError(w, err)
		return
	}

	res, err := h.auth.Token(ctx, &req)
	if err != nil {
		h.logger.ErrorContext(ctx, "token exchange failed",
			"error", err,
			"request_id", requestID,
			"client_id", req.ClientID,
		)
		httpError.WriteError(w, err)
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
		httpError.WriteError(w, err)
		return
	}

	h.logger.InfoContext(ctx, "user info retrieved successfully",
		"request_id", requestID,
		"session_id", sessionIDStr,
	)

	respond.WriteJSON(w, http.StatusOK, res)
}

func (h *Handler) HandleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)
	userIDParam := chi.URLParam(r, "user_id")
	userID, err := uuid.Parse(userIDParam)
	if err != nil {
		h.logger.WarnContext(ctx, "invalid user_id in delete request",
			"user_id", userIDParam,
			"request_id", requestID,
		)
		httpError.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid user_id"))
		return
	}

	if err := h.auth.DeleteUser(ctx, userID); err != nil {
		h.logger.ErrorContext(ctx, "failed to delete user",
			"error", err,
			"user_id", userID.String(),
			"request_id", requestID,
		)
		httpError.WriteError(w, err)
		return
	}

	h.logger.InfoContext(ctx, "user deleted via admin API",
		"user_id", userID.String(),
		"request_id", requestID,
	)

	w.WriteHeader(http.StatusNoContent)
}

func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
