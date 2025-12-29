package handler

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"credo/internal/auth/metrics"
	"credo/internal/auth/models"
	"credo/internal/auth/ports"
	"credo/internal/platform/config"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/httputil"
	auth "credo/pkg/platform/middleware/auth"
	"credo/pkg/platform/middleware/metadata"
	request "credo/pkg/platform/middleware/request"
)

// Service defines the auth use cases consumed by HTTP handlers.
type Service interface {
	Authorize(ctx context.Context, req *models.AuthorizationRequest) (*models.AuthorizationResult, error)
	Token(ctx context.Context, req *models.TokenRequest) (*models.TokenResult, error)
	UserInfo(ctx context.Context, sessionID string) (*models.UserInfoResult, error)
	ListSessions(ctx context.Context, userID id.UserID, currentSessionID id.SessionID) (*models.SessionsResult, error)
	RevokeSession(ctx context.Context, userID id.UserID, sessionID id.SessionID) error
	LogoutAll(ctx context.Context, userID id.UserID, currentSessionID id.SessionID, exceptCurrent bool) (*models.LogoutAllResult, error)
	DeleteUser(ctx context.Context, userID id.UserID) error
	RevokeToken(ctx context.Context, token string, tokenTypeHint string) error
}

// Handler wires HTTP auth endpoints to the auth service and rate limiting.
type Handler struct {
	auth             Service
	ratelimit        ports.RateLimitPort
	metrics          *metrics.Metrics
	logger           *slog.Logger
	deviceCookieName string
	deviceCookieAge  int
}

// TODO: pass device config in main.go
// New constructs an auth HTTP handler and applies device cookie defaults.
func New(auth Service, ratelimit ports.RateLimitPort, m *metrics.Metrics, logger *slog.Logger, deviceCookieName string, deviceCookieMaxAge int) *Handler {
	if deviceCookieName == "" {
		deviceCookieName = config.DefaultDeviceCookieName
	}
	if deviceCookieMaxAge <= 0 {
		deviceCookieMaxAge = config.DefaultDeviceCookieMaxAge
	}

	return &Handler{
		auth:             auth,
		ratelimit:        ratelimit,
		metrics:          m,
		logger:           logger,
		deviceCookieName: deviceCookieName,
		deviceCookieAge:  deviceCookieMaxAge,
	}
}

// Register wires public auth routes onto the provided router.
func (h *Handler) Register(r chi.Router) {
	r.Post("/auth/authorize", h.HandleAuthorize)
	r.Post("/auth/token", h.HandleToken)
	r.Get("/auth/userinfo", h.HandleUserInfo)
	r.Get("/auth/sessions", h.HandleListSessions)
	r.Delete("/auth/sessions/{session_id}", h.HandleRevokeSession)
	r.Post("/auth/logout-all", h.HandleLogoutAll)
	r.Post("/auth/revoke", h.HandleRevoke)
}

// RegisterAdmin wires admin auth routes onto the provided router.
func (h *Handler) RegisterAdmin(r chi.Router) {
	r.Delete("/admin/auth/users/{user_id}", h.HandleAdminDeleteUser)
}

// HandleAuthorize implements POST /auth/authorize
// Initiates an authentication session for a user by email.
// If the user doesn't exist, creates them automatically.
//
// Input: { "email": "user@example.com", "client_id": "demo-client", "scopes": [...], "redirect_uri": "...", "state": "..." }
// Output: { "code": "authz_...", "redirect_uri": "https://..." }
func (h *Handler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)
	clientIP := metadata.GetClientIP(ctx)

	req, ok := httputil.DecodeJSON[models.AuthorizationRequest](w, r, h.logger, ctx, requestID)
	if !ok {
		return
	}

	// Check auth rate limit using email + IP composite key
	// Rate limit before validation to count all attempts
	if rl := h.checkRateLimit(ctx, requestID, req.Email, clientIP, "authorize"); !rl.Allowed {
		h.writeRateLimitError(w, rl.RetryAfter)
		return
	}

	// Normalize and validate after rate limit check
	req.Normalize()
	if err := req.Validate(); err != nil {
		httputil.WriteError(w, err)
		return
	}

	res, err := h.auth.Authorize(ctx, req)
	if err != nil {
		h.logger.ErrorContext(ctx, "authorize failed",
			"error", err,
			"request_id", requestID,
			"client_id", req.ClientID,
		)
		httputil.WriteError(w, err)
		return
	}

	h.logger.InfoContext(ctx, "authorize successful",
		"request_id", requestID,
		"client_id", req.ClientID,
	)

	// Set device ID cookie (Phase 1: soft launch — generate cookie, no enforcement).
	// Note: Cookie EXTRACTION is handled by Device middleware; cookie SETTING must remain here.
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

	httputil.WriteJSON(w, http.StatusOK, res)
}

// HandleToken implements POST /auth/token.
// It enforces rate limits, validates the request, invokes the auth service,
// and returns token response data.
func (h *Handler) HandleToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)
	clientIP := metadata.GetClientIP(ctx)

	req, ok := httputil.DecodeJSON[models.TokenRequest](w, r, h.logger, ctx, requestID)
	if !ok {
		return
	}

	// Check token rate limit using client_id + IP composite key
	// Rate limit before validation to count all attempts
	if req.ClientID != "" {
		if rl := h.checkRateLimit(ctx, requestID, req.ClientID, clientIP, "token"); !rl.Allowed {
			h.writeRateLimitError(w, rl.RetryAfter)
			return
		}
	}

	// Normalize and validate after rate limit check
	req.Normalize()
	if err := req.Validate(); err != nil {
		httputil.WriteError(w, err)
		return
	}

	res, err := h.auth.Token(ctx, req)
	if err != nil {
		h.logger.ErrorContext(ctx, "token exchange failed",
			"error", err,
			"request_id", requestID,
			"client_id", req.ClientID,
		)
		httputil.WriteError(w, err)
		return
	}

	h.logger.InfoContext(ctx, "token exchange successful",
		"request_id", requestID,
		"client_id", req.ClientID,
	)

	httputil.WriteJSON(w, http.StatusOK, res)
}

// HandleUserInfo implements GET /auth/userinfo.
// It resolves the session from context and returns OIDC user info.
func (h *Handler) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	sessionID, ok := h.requireSessionIDFromContext(ctx, w, requestID)
	if !ok {
		return
	}

	res, err := h.auth.UserInfo(ctx, sessionID.String())
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to get user info",
			"error", err,
			"request_id", requestID,
			"session_id", sessionID.String(),
		)
		httputil.WriteError(w, err)
		return
	}

	h.logger.InfoContext(ctx, "user info retrieved successfully",
		"request_id", requestID,
		"session_id", sessionID.String(),
	)

	httputil.WriteJSON(w, http.StatusOK, res)
}

// HandleListSessions implements GET /auth/sessions for the current user.
func (h *Handler) HandleListSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	userID, ok := h.requireUserIDFromContext(ctx, w, requestID)
	if !ok {
		return
	}

	currentSessionID, ok := h.requireSessionIDFromContext(ctx, w, requestID)
	if !ok {
		return
	}

	res, err := h.auth.ListSessions(ctx, userID, currentSessionID)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to list sessions",
			"error", err,
			"request_id", requestID,
			"user_id", userID.String(),
		)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, res)
}

// HandleRevokeSession implements DELETE /auth/sessions/{session_id}.
// It verifies session ownership before revocation.
func (h *Handler) HandleRevokeSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	userID, ok := h.requireUserIDFromContext(ctx, w, requestID)
	if !ok {
		return
	}

	sessionID, ok := h.requireSessionIDFromPath(r, w, requestID)
	if !ok {
		return
	}

	if err := h.auth.RevokeSession(ctx, userID, sessionID); err != nil {
		h.logger.ErrorContext(ctx, "failed to revoke session",
			"error", err,
			"request_id", requestID,
			"session_id", sessionID.String(),
		)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, &models.SessionRevocationResult{
		Revoked:   true,
		SessionID: sessionID.String(),
		Message:   "Session revoked successfully",
	})
}

// HandleLogoutAll implements POST /auth/logout-all
// Revokes all sessions for the authenticated user, optionally keeping the current session.
//
// Query params: except_current=true (default) keeps current session active
// Output: { "revoked_count": 3, "message": "..." }
//
// Design note: Partial revocation on error is intentional. The user can retry,
// and each revocation is independently idempotent.
func (h *Handler) HandleLogoutAll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	userID, ok := h.requireUserIDFromContext(ctx, w, requestID)
	if !ok {
		return
	}

	currentSessionID, ok := h.requireSessionIDFromContext(ctx, w, requestID)
	if !ok {
		return
	}

	exceptCurrent := r.URL.Query().Get("except_current") != "false"

	res, err := h.auth.LogoutAll(ctx, userID, currentSessionID, exceptCurrent)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to logout all sessions",
			"error", err,
			"request_id", requestID,
			"user_id", userID.String(),
		)
		httputil.WriteError(w, err)
		return
	}

	h.logger.InfoContext(ctx, "logout all completed",
		"request_id", requestID,
		"user_id", userID.String(),
		"revoked_count", res.RevokedCount,
		"except_current", exceptCurrent,
	)

	message := strconv.Itoa(res.RevokedCount) + " sessions revoked"
	if res.RevokedCount == 1 {
		message = "1 session revoked"
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"revoked_count": res.RevokedCount,
		"message":       message,
	})
}

// rateLimitResult holds the outcome of a rate limit check.
type rateLimitResult struct {
	// Allowed indicates whether the request is permitted (true) or rate-limited (false).
	Allowed bool
	// RetryAfter is the number of seconds to wait before retrying (0 if Allowed is true).
	RetryAfter int
}

// checkRateLimit checks if a request is within rate limits.
// Returns allowed=true on success or if rate limiter is unavailable (fail-open).
// identifier is typically a user ID or email; clientIP is the request source IP.
func (h *Handler) checkRateLimit(ctx context.Context, requestID string, identifier string, clientIP string, endpoint string) rateLimitResult {
	if h.ratelimit == nil {
		return rateLimitResult{Allowed: true}
	}

	result, err := h.ratelimit.CheckAuthRateLimit(ctx, identifier, clientIP)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to check rate limit",
			"error", err,
			"request_id", requestID,
			"endpoint", endpoint,
		)
		if h.metrics != nil {
			h.metrics.IncrementRateLimitCheckErrors(endpoint)
		}
		// TODO: this will change when fail closed is implemented
		// Fail open - don't block if rate limiter is unavailable
		return rateLimitResult{Allowed: true}
	}

	if !result.Allowed {
		h.logger.WarnContext(ctx, "rate limit exceeded",
			"request_id", requestID,
			"retry_after", result.RetryAfter,
			"endpoint", endpoint,
		)
	}

	return rateLimitResult{Allowed: result.Allowed, RetryAfter: result.RetryAfter}
}

// writeRateLimitError writes a 429 Too Many Requests response.
func (h *Handler) writeRateLimitError(w http.ResponseWriter, retryAfter int) {
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	httputil.WriteJSON(w, http.StatusTooManyRequests, map[string]any{
		"error":       "rate_limit_exceeded",
		"message":     "Too many requests. Please try again later.",
		"retry_after": retryAfter,
	})
}

// HandleAdminDeleteUser implements DELETE /admin/auth/users/{user_id}.
// It deletes the user and related sessions as an administrative action.
func (h *Handler) HandleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	userID, ok := h.requireUserIDFromPath(r, w, requestID)
	if !ok {
		return
	}

	if err := h.auth.DeleteUser(ctx, userID); err != nil {
		h.logger.ErrorContext(ctx, "failed to delete user",
			"error", err,
			"user_id", userID.String(),
			"request_id", requestID,
		)
		httputil.WriteError(w, err)
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

// HandleRevoke implements POST /auth/revoke
// Revokes access tokens and refresh tokens, effectively logging out the user.
// Follows RFC 7009 token revocation spec.
//
// Input: { "token": "ref_...", "token_type_hint": "refresh_token" }
// Output: { "revoked": true, "message": "Token revoked successfully" }
func (h *Handler) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	req, ok := httputil.DecodeAndPrepare[models.RevokeTokenRequest](w, r, h.logger, ctx, requestID)
	if !ok {
		return
	}

	if err := h.auth.RevokeToken(ctx, req.Token, req.TokenTypeHint); err != nil {
		h.logger.ErrorContext(ctx, "failed to revoke token",
			"error", err,
			"request_id", requestID,
		)
		httputil.WriteError(w, err)
		return
	}

	h.logger.InfoContext(ctx, "token revoked successfully",
		"token_type_hint", req.TokenTypeHint,
		"request_id", requestID,
	)

	// RFC 7009 Section 2.2: Return 200 even if token was already revoked (idempotent)
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"revoked": true,
		"message": "Token revoked successfully",
	})
}

// requireUserIDFromContext retrieves the typed user ID from auth context.
// Returns false if not set (error response already written).
// Uses 401 Unauthorized since context IDs come from the JWT token.
func (h *Handler) requireUserIDFromContext(ctx context.Context, w http.ResponseWriter, requestID string) (id.UserID, bool) {
	userID := auth.GetUserID(ctx)
	if userID.IsNil() {
		h.logger.WarnContext(ctx, "user_id missing from auth context",
			"request_id", requestID,
		)
		httputil.WriteError(w, dErrors.New(dErrors.CodeUnauthorized, "invalid token"))
		return id.UserID{}, false
	}
	return userID, true
}

// requireSessionIDFromContext retrieves the typed session ID from auth context.
// Returns false if not set (error response already written).
// Uses 401 Unauthorized since context IDs come from the JWT token.
func (h *Handler) requireSessionIDFromContext(ctx context.Context, w http.ResponseWriter, requestID string) (id.SessionID, bool) {
	sessionID := auth.GetSessionID(ctx)
	if sessionID.IsNil() {
		h.logger.WarnContext(ctx, "session_id missing from auth context",
			"request_id", requestID,
		)
		httputil.WriteError(w, dErrors.New(dErrors.CodeUnauthorized, "invalid token"))
		return id.SessionID{}, false
	}
	return sessionID, true
}

// requireSessionIDFromPath parses session ID from URL path parameter.
// Returns false if parsing fails (error response already written).
func (h *Handler) requireSessionIDFromPath(r *http.Request, w http.ResponseWriter, requestID string) (id.SessionID, bool) {
	ctx := r.Context()
	sessionIDStr := chi.URLParam(r, "session_id")
	sessionID, err := id.ParseSessionID(sessionIDStr)
	if err != nil {
		h.logger.WarnContext(ctx, "invalid session_id in path",
			"session_id", sessionIDStr,
			"request_id", requestID,
		)
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid session_id"))
		return id.SessionID{}, false
	}
	return sessionID, true
}

// requireUserIDFromPath parses user ID from URL path parameter.
// Returns false if parsing fails (error response already written).
func (h *Handler) requireUserIDFromPath(r *http.Request, w http.ResponseWriter, requestID string) (id.UserID, bool) {
	ctx := r.Context()
	userIDStr := chi.URLParam(r, "user_id")
	userID, err := id.ParseUserID(userIDStr)
	if err != nil {
		h.logger.WarnContext(ctx, "invalid user_id in path",
			"user_id", userIDStr,
			"request_id", requestID,
		)
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid user_id"))
		return id.UserID{}, false
	}
	return userID, true
}
