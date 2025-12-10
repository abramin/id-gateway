package httptransport

import (
	"github.com/go-chi/chi/v5"

	authHandler "credo/internal/auth/handler"
	consentHandler "credo/internal/consent/handler"
)

// HTTPHandler defines the interface for domain handlers that register their routes.
type HTTPHandler interface {
	Register(r chi.Router)
}

// RegisterAuthHandler registers the authentication handler routes.
func RegisterAuthHandler(r chi.Router, h *authHandler.Handler) {
	h.Register(r)
}

// RegisterConsentHandler registers the consent handler routes.
func RegisterConsentHandler(r chi.Router, h *consentHandler.Handler) {
	h.Register(r)
}
