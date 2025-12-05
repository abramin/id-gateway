package httptransport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"

	authModel "id-gateway/internal/auth/models"
	"id-gateway/internal/platform/middleware"
	dErrors "id-gateway/pkg/domain-errors"
	s "id-gateway/pkg/string"
)

// AuthHandler handles authentication endpoints including authorize, token, and userinfo.
// Implements the OIDC-lite flow described in PRD-001.
type AuthHandler struct {
	auth   AuthService
	logger *slog.Logger
}

// AuthService defines the interface for authentication operations.grant_type must be one of
type AuthService interface {
	Authorize(ctx context.Context, req *authModel.AuthorizationRequest) (*authModel.AuthorizationResult, error)
	Token(ctx context.Context, req *authModel.TokenRequest) (*authModel.TokenResult, error)
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
		h.logger.Warn("failed to decode token request",
			"error", err,
			"request_id", requestID,
		)
		writeError(w, dErrors.New(dErrors.CodeInvalidRequest, "Invalid JSON in request body"))
		return
	}
	err := validateAuthRequest(&req)
	if err != nil {
		h.logger.Warn("invalid token request",
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
		h.logger.Error("token failed",
			"error", err,
			"request_id", requestID,
			"email", req.Email,
		)
		writeError(w, err)
		return
	}

	h.logger.Info("token successful",
		"request_id", requestID,
		"code", res.Code,
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
		h.logger.Warn("failed to decode token request",
			"error", err,
			"request_id", requestID,
		)
		writeError(w, dErrors.New(dErrors.CodeInvalidRequest, "Invalid JSON in request body"))
		return
	}
	err := validateAuthRequest(&req)
	if err != nil {
		h.logger.Warn("invalid token request",
			"error", err,
			"request_id", requestID,
			"code", req.Code,
		)
		writeError(w, err)
		return
	}
	sanitizeTokenRequest(&req)

	res, err := h.auth.Token(ctx, &req)
	if err != nil {
		h.logger.Error("token exchange failed",
			"error", err,
			"request_id", requestID,
			"code", req.Code,
		)
		writeError(w, err)
		return
	}

	h.logger.Info("token exchange successful",
		"request_id", requestID,
	)

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

	var req authModel.UserInfoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("failed to decode userinfo request",
			"error", err,
			"request_id", requestID,
		)
		writeError(w, dErrors.New(dErrors.CodeInvalidRequest, "Invalid JSON in request body"))
		return
	}

	err := validateAuthRequest(&req)
	if err != nil {
		h.logger.Warn("invalid userinfo request",
			"error", err,
			"request_id", requestID,
		)
		writeError(w, err)
		return
	}
	sanitizeUserInfoRequest(&req)
	h.logger.Info("userinfo request successful",
		"request_id", requestID,
	)

}

func sanitizeUserInfoRequest(req *authModel.UserInfoRequest) {
	s.TrimStrings(&req.AccessToken)
}

func sanitizeAuthorizationRequest(req *authModel.AuthorizationRequest) {
	s.TrimStrings(&req.Email, &req.ClientID, &req.RedirectURI, &req.State)
	s.TrimSlice(req.Scopes)
}

func sanitizeTokenRequest(req *authModel.TokenRequest) {
	s.TrimStrings(&req.GrantType, &req.Code, &req.RedirectURI, &req.ClientID)
}

var authValidator = newAuthValidator()

func newAuthValidator() *validator.Validate {
	v := validator.New(validator.WithRequiredStructEnabled())
	_ = v.RegisterValidation("notblank", func(fl validator.FieldLevel) bool {
		return strings.TrimSpace(fl.Field().String()) != ""
	})
	return v
}

func validateAuthRequest(req any) error {
	if err := authValidator.Struct(req); err != nil {
		return dErrors.New(dErrors.CodeValidation, validationErrorMessage(err))
	}
	return nil
}

func validationErrorMessage(err error) string {
	var validationErrs validator.ValidationErrors
	if !errors.As(err, &validationErrs) || len(validationErrs) == 0 {
		return "invalid request body"
	}

	fe := validationErrs[0]
	field := s.ToSnakeCase(fe.Field())

	switch fe.ActualTag() {
	case "required":
		return fmt.Sprintf("%s is required", field)
	case "email":
		return fmt.Sprintf("%s must be a valid email", field)
	case "url":
		return fmt.Sprintf("%s must be a valid url", field)
	case "min":
		return fmt.Sprintf("%s must be at least %s", field, fe.Param())
	case "max":
		return fmt.Sprintf("%s must be at most %s", field, fe.Param())
	case "oneof":
		return fmt.Sprintf("%s must be one of [%s]", field, fe.Param())
	case "notblank":
		return fmt.Sprintf("%s must not be blank", field)
	default:
		return fmt.Sprintf("%s is invalid", field)
	}
}
