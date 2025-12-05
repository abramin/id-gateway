package httptransport

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	authModel "id-gateway/internal/auth/models"
	jwttoken "id-gateway/internal/jwt_token"
	"id-gateway/internal/platform/metrics"
	"id-gateway/internal/platform/middleware"
	dErrors "id-gateway/pkg/domain-errors"
	s "id-gateway/pkg/string"
	"id-gateway/pkg/validation"
)

// AuthHandler handles authentication endpoints including authorize, token, and userinfo.
// Implements the OIDC-lite flow described in PRD-001.
type AuthHandler struct {
	regulatedMode bool
	auth          AuthService
	logger        *slog.Logger
	metrics       *metrics.Metrics
}

// AuthService defines the interface for authentication operations.grant_type must be one of
type AuthService interface {
	Authorize(ctx context.Context, req *authModel.AuthorizationRequest) (*authModel.AuthorizationResult, error)
	Token(ctx context.Context, req *authModel.TokenRequest) (*authModel.TokenResult, error)
	UserInfo(ctx context.Context, sessionID uuid.UUID) (*authModel.UserInfoResult, error)
}

// NewAuthHandler creates a new AuthHandler with the given service and logger.
func NewAuthHandler(auth AuthService, logger *slog.Logger, regulatedMode bool, metrics *metrics.Metrics) *AuthHandler {
	return &AuthHandler{
		regulatedMode: regulatedMode,
		auth:          auth,
		logger:        logger,
		metrics:       metrics,
	}
}

// Register registers the auth routes with the chi router.
func (h *AuthHandler) Register(r chi.Router) {
	r.Use(middleware.Recovery(h.logger))
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger(h.logger))
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(middleware.ContentTypeJSON)
	r.Use(middleware.LatencyMiddleware(h.metrics))

	r.Post("/auth/authorize", h.handleAuthorize)
	r.Post("/auth/token", h.handleToken)
	r.Get("/auth/userinfo", h.handleUserInfo)
}

// handleAuthorize implements POST /auth/authorize per PRD-001 FR-1.
// Initiates an authentication session for a user by email.
// If the user doesn't exist, creates them automatically.
//
// Input: { "email": "user@example.com", "client_id": "demo-client", "scopes": [...], "redirect_uri": "...", "state": "..." }
// Output: { "session_id": "sess_...", "redirect_uri": "https://..." }
func (h *AuthHandler) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)

	var req authModel.AuthorizationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.WarnContext(ctx, "failed to decode authorize request",
			"error", err,
			"request_id", requestID,
		)
		writeError(w, dErrors.New(dErrors.CodeInvalidRequest, "Invalid JSON in request body"))
		return
	}
	s.Sanitize(&req)
	if err := validation.Validate(&req); err != nil {
		h.logger.WarnContext(ctx, "invalid authorize request",
			"error", err,
			"request_id", requestID,
		)
		writeError(w, err)
		return
	}

	res, err := h.auth.Authorize(ctx, &req)
	if err != nil {
		h.logger.ErrorContext(ctx, "authorize failed",
			"error", err,
			"request_id", requestID,
			"client_id", req.ClientID,
		)
		writeError(w, err)
		return
	}

	h.logger.InfoContext(ctx, "authorize successful",
		"request_id", requestID,
		"client_id", req.ClientID,
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// Note: We ignore encoding errors here since the response has already started.
	// Proper error handling would require buffering the response.
	_ = json.NewEncoder(w).Encode(map[string]string{
		"code":         res.Code,
		"redirect_uri": res.RedirectURI,
	})
}

func (h *AuthHandler) handleToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)

	var req authModel.TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.WarnContext(ctx, "failed to decode token request",
			"error", err,
			"request_id", requestID,
		)
		writeError(w, dErrors.New(dErrors.CodeInvalidRequest, "Invalid JSON in request body"))
		return
	}
	s.Sanitize(&req)
	if err := validation.Validate(&req); err != nil {
		h.logger.WarnContext(ctx, "invalid token request",
			"error", err,
			"request_id", requestID,
		)
		writeError(w, err)
		return
	}

	res, err := h.auth.Token(ctx, &req)
	if err != nil {
		h.logger.ErrorContext(ctx, "token exchange failed",
			"error", err,
			"request_id", requestID,
			"client_id", req.ClientID,
		)
		writeError(w, err)
		return
	}

	h.logger.InfoContext(ctx, "token exchange successful",
		"request_id", requestID,
		"client_id", req.ClientID,
	)
	if h.metrics != nil { // allow tests to skip instrumentation
		h.metrics.IncrementTokenRequests()
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// Note: We ignore encoding errors here since the response has already started.
	// Proper error handling would require buffering the response.
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": res.AccessToken,
		"id_token":     res.IDToken,
		"expires_in":   res.ExpiresIn,
	})
}

func (h *AuthHandler) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)

	session_id, err := jwttoken.ExtractSessionIDFromAuthHeader(r.Header.Get("Authorization"))
	if err != nil {
		h.logger.WarnContext(ctx, "missing or invalid access token",
			"request_id", requestID,
		)
		writeError(w, dErrors.New(dErrors.CodeUnauthorized, "missing or invalid access token"))
		if h.metrics != nil {
			h.metrics.IncrementAuthFailures()
		}
		return
	}
	session_uuid, err := uuid.Parse(session_id)
	if err != nil {
		h.logger.WarnContext(ctx, "invalid session id format",
			"error", err,
			"request_id", requestID,
		)
		writeError(w, dErrors.New(dErrors.CodeInvalidInput, "invalid session id format"))
		return
	}

	userInfo, err := h.auth.UserInfo(ctx, session_uuid)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to get user info",
			"error", err,
			"request_id", requestID,
			"session_id", session_id,
		)
		writeError(w, err)
		return
	}

	h.logger.InfoContext(ctx, "user info retrieved successfully",
		"request_id", requestID,
		"session_id", session_id,
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// Note: We ignore encoding errors here since the response has already started.
	// Proper error handling would require buffering the response.
	_ = json.NewEncoder(w).Encode(userInfo)

}
