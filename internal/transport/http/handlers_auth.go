package httptransport

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"

	authModel "id-gateway/internal/auth/models"
	"id-gateway/internal/platform/middleware"
	httpErrors "id-gateway/pkg/http-errors"
)

// AuthHandler handles authentication endpoints including authorize, token, and userinfo.
// Implements the OIDC-lite flow described in PRD-001.
type AuthHandler struct {
	auth   AuthService
	logger *slog.Logger
}

// AuthService defines the interface for authentication operations.
type AuthService interface {
	Authorize(ctx context.Context, req *authModel.AuthorizationRequest) (*authModel.AuthorizationResult, error)
}

// NewAuthHandler creates a new AuthHandler with the given service and logger.
func NewAuthHandler(auth AuthService, logger *slog.Logger) *AuthHandler {
	return &AuthHandler{
		auth:   auth,
		logger: logger,
	}
}

// Register registers the auth routes with the chi router.
func (h *AuthHandler) Register(r chi.Router) {
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
		h.logger.Warn("failed to decode authorization request",
			"error", err,
			"request_id", requestID,
		)
		writeJSONError(w, httpErrors.CodeInvalidRequest, "Invalid JSON in request body", http.StatusBadRequest)
		return
	}
	err := validateAuthorizationRequest(&req)
	if err != nil {
		h.logger.Warn("invalid authorization request",
			"error", err,
			"request_id", requestID,
			"email", req.Email,
		)
		writeError(w, err)
		return
	}
	sanitizeAuthorizationRequest(&req)

	res, err := h.auth.Authorize(ctx, &req)
	if err != nil {
		h.logger.Error("authorization failed",
			"error", err,
			"request_id", requestID,
			"email", req.Email,
		)
		writeError(w, err)
		return
	}

	h.logger.Info("authorization successful",
		"request_id", requestID,
		"session_id", res.SessionID,
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// Note: We ignore encoding errors here since the response has already started.
	// Proper error handling would require buffering the response.
	_ = json.NewEncoder(w).Encode(map[string]string{
		"session_id":   res.SessionID.String(),
		"redirect_uri": res.RedirectURI,
	})
}

func (h *AuthHandler) handleToken(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, "/auth/token")
}

func (h *AuthHandler) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, "/auth/userinfo")
}

func (h *AuthHandler) notImplemented(w http.ResponseWriter, endpoint string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message":  "TODO: implement handler",
		"endpoint": endpoint,
	})
}

func sanitizeAuthorizationRequest(req *authModel.AuthorizationRequest) {
	req.Email = strings.TrimSpace(req.Email)
	req.ClientID = strings.TrimSpace(req.ClientID)
	req.RedirectURI = strings.TrimSpace(req.RedirectURI)
	req.State = strings.TrimSpace(req.State)
	for i, scope := range req.Scopes {
		req.Scopes[i] = strings.TrimSpace(scope)
	}
}

func validateAuthorizationRequest(req *authModel.AuthorizationRequest) error {
	if err := authValidator.Struct(req); err != nil {
		return httpErrors.New(httpErrors.CodeInvalidInput, "invalid request body")
	}
	return nil
}

var authValidator = newAuthValidator()

func newAuthValidator() *validator.Validate {
	v := validator.New(validator.WithRequiredStructEnabled())
	_ = v.RegisterValidation("notblank", func(fl validator.FieldLevel) bool {
		return strings.TrimSpace(fl.Field().String()) != ""
	})
	return v
}
