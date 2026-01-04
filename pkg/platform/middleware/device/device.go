package device

import (
	"net/http"

	"credo/pkg/requestcontext"
)

// DeviceConfig holds configuration for the Device middleware.
type DeviceConfig struct {
	// FingerprintFn computes a device fingerprint from the User-Agent string.
	// This is typically device.Service.ComputeFingerprint.
	FingerprintFn func(userAgent string) string

	// CookieName is the name of the device ID cookie (e.g., "__Secure-Device-ID").
	CookieName string
}

// Device extracts device ID from cookie and pre-computes device fingerprint.
// It should be registered after ClientMetadata middleware (which extracts User-Agent).
//
// The middleware:
// 1. Extracts device ID from the configured cookie and injects into context
// 2. Pre-computes device fingerprint from User-Agent and injects into context
//
// Cookie SETTING is handled by the auth handler (response-side concern).
func Device(cfg *DeviceConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Extract device ID from cookie (if present)
			if cfg.CookieName != "" {
				if cookie, err := r.Cookie(cfg.CookieName); err == nil && cookie != nil {
					ctx = requestcontext.WithDeviceID(ctx, cookie.Value)
				}
			}

			// Pre-compute fingerprint from User-Agent (already in context from ClientMetadata)
			if cfg.FingerprintFn != nil {
				userAgent := requestcontext.UserAgent(ctx)
				if userAgent != "" {
					fingerprint := cfg.FingerprintFn(userAgent)
					ctx = requestcontext.WithDeviceFingerprint(ctx, fingerprint)
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
