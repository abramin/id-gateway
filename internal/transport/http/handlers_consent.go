package httptransport

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	consentModel "id-gateway/internal/consent/models"
	jwttoken "id-gateway/internal/jwt_token"
	"id-gateway/internal/platform/metrics"
	"id-gateway/internal/platform/middleware"
	dErrors "id-gateway/pkg/domain-errors"
)

type ConsentService interface {
	Grant(ctx context.Context, userID string, purpose consentModel.ConsentPurpose, ttl time.Duration) error
	Revoke(ctx context.Context, userID string, purpose consentModel.ConsentPurpose) error
	Require(ctx context.Context, userID string, purpose consentModel.ConsentPurpose, now time.Time) error
	List(ctx context.Context, userID string) ([]*consentModel.ConsentRecord, error)
}

// ConsentHandler handles consent-related endpoints.
type ConsentHandler struct {
	logger     *slog.Logger
	consent    ConsentService
	metrics    *metrics.Metrics
	consentTTL time.Duration
}

func (h *ConsentHandler) Register(r chi.Router) {
	consentRouter := chi.NewRouter()
	consentRouter.Use(middleware.Recovery(h.logger))
	consentRouter.Use(middleware.RequestID)
	consentRouter.Use(middleware.Logger(h.logger))
	consentRouter.Use(middleware.Timeout(30 * time.Second))
	consentRouter.Use(middleware.ContentTypeJSON)
	consentRouter.Use(middleware.LatencyMiddleware(h.metrics))

	consentRouter.Post("/auth/consent", h.handleGrantConsent)
	consentRouter.Post("/auth/consent/revoke", h.handleRevokeConsent)
	consentRouter.Get("/auth/consent", h.handleGetConsent)

	r.Mount("/", consentRouter)
}

func NewConsentHandler(consent ConsentService, logger *slog.Logger, metrics *metrics.Metrics) *ConsentHandler {
	return &ConsentHandler{
		logger:  logger,
		consent: consent,
		metrics: metrics,
	}
}

// NewConsentHandler creates a new ConsentHandler with the given logger.
func (h *ConsentHandler) handleGrantConsent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)
	ok, err := jwttoken.ValidateAuthToken(r.Header.Get("Authorization"))
	if !ok || err != nil {
		h.logger.WarnContext(ctx, "missing or invalid access token",
			"request_id", requestID,
		)
		writeError(w, dErrors.New(dErrors.CodeUnauthorized, "missing or invalid access token"))
		if h.metrics != nil {
			h.metrics.IncrementAuthFailures()
		}
		return
	}

	var grantReq *consentModel.GrantConsentRequest
	// Purposes array must not be empty
	err = json.NewDecoder(r.Body).Decode(grantReq)
	if err != nil {
		h.logger.WarnContext(ctx, "invalid grant consent request",
			"request_id", requestID,
			"error", err.Error(),
		)
		writeError(w, dErrors.New(dErrors.CodeBadRequest, "invalid request body"))
		return
	}

	if len(grantReq.Purposes) == 0 {
		h.logger.WarnContext(ctx, "empty purposes in grant consent request",
			"request_id", requestID,
		)
		writeError(w, dErrors.New(dErrors.CodeBadRequest, "purposes array must not be empty"))
		return
	}
	// Each purpose must match ConsentPurpose enum
	for _, purpose := range grantReq.Purposes {
		switch purpose {
		case consentModel.ConsentPurposeLogin,
			consentModel.ConsentPurposeRegistryCheck,
			consentModel.ConsentPurposeVCIssuance,
			consentModel.ConsentPurposeDecision,
			consentModel.ConsentMarketing:
			// valid purpose
		default:
			h.logger.WarnContext(ctx, "invalid purpose in grant consent request",
				"request_id", requestID,
				"purpose", purpose,
			)
			writeError(w, dErrors.New(dErrors.CodeBadRequest, "invalid purpose: "+string(purpose)))
			return
		}
	}

	userID := ctx.Value(middleware.ContextKeyUserID).(string)

	// Grant consent for each purpose
	for _, purpose := range grantReq.Purposes {
		err = h.consent.Grant(ctx, userID, purpose, h.consentTTL)
		if err != nil {
			h.logger.ErrorContext(ctx, "failed to grant consent",
				"request_id", requestID,
				"purpose", purpose,
				"error", err.Error(),
			)
			writeError(w, dErrors.New(dErrors.CodeInternal, "failed to grant consent"))
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)

}

func (h *ConsentHandler) handleRevokeConsent(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, "/auth/consent/revoke")
}
func (h *ConsentHandler) handleGetConsent(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, "/auth/consent")
}
func (h *ConsentHandler) notImplemented(w http.ResponseWriter, path string) {
	h.logger.Warn("Not implemented", slog.String("path", path))
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}
