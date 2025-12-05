package httptransport

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	consentModel "id-gateway/internal/consent/models"
	"id-gateway/internal/platform/metrics"
	"id-gateway/internal/platform/middleware"

	"github.com/go-chi/chi/v5"
)

type ConsentService interface {
	Grant(ctx context.Context, userID string, purpose consentModel.ConsentPurpose, ttl time.Duration) error
	Revoke(ctx context.Context, userID string, purpose consentModel.ConsentPurpose) error
	Require(ctx context.Context, userID string, purpose consentModel.ConsentPurpose, now time.Time) error
	List(ctx context.Context, userID string) ([]*consentModel.ConsentRecord, error)
}

// ConsentHandler handles consent-related endpoints.
type ConsentHandler struct {
	logger  *slog.Logger
	consent ConsentService
	metrics *metrics.Metrics
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

// NewConsentHandler creates a new ConsentHandler with the given logger.
func (h *ConsentHandler) handleGrantConsent(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, "/auth/consent")
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
