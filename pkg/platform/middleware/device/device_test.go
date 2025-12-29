package device

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"credo/pkg/requestcontext"
)

func TestDeviceMiddleware(t *testing.T) {
	t.Run("extracts device ID from cookie", func(t *testing.T) {
		cfg := &DeviceConfig{
			CookieName: "__Secure-Device-ID",
		}

		var capturedDeviceID string
		handler := Device(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedDeviceID = requestcontext.DeviceID(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.AddCookie(&http.Cookie{Name: "__Secure-Device-ID", Value: "device-123"})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, "device-123", capturedDeviceID)
	})

	t.Run("returns empty string when cookie missing", func(t *testing.T) {
		cfg := &DeviceConfig{
			CookieName: "__Secure-Device-ID",
		}

		var capturedDeviceID string
		handler := Device(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedDeviceID = requestcontext.DeviceID(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Empty(t, capturedDeviceID)
	})

	t.Run("skips cookie extraction when cookie name empty", func(t *testing.T) {
		cfg := &DeviceConfig{
			CookieName: "", // Empty cookie name
		}

		var capturedDeviceID string
		handler := Device(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedDeviceID = requestcontext.DeviceID(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.AddCookie(&http.Cookie{Name: "__Secure-Device-ID", Value: "device-123"})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Empty(t, capturedDeviceID)
	})

	t.Run("computes fingerprint from user agent", func(t *testing.T) {
		cfg := &DeviceConfig{
			FingerprintFn: func(ua string) string {
				return "fp-" + ua
			},
		}

		var capturedFingerprint string
		handler := Device(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedFingerprint = requestcontext.DeviceFingerprint(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		// Pre-inject user agent via metadata middleware context
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := requestcontext.WithClientMetadata(req.Context(), "127.0.0.1", "Mozilla/5.0")
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, "fp-Mozilla/5.0", capturedFingerprint)
	})

	t.Run("skips fingerprint when user agent empty", func(t *testing.T) {
		cfg := &DeviceConfig{
			FingerprintFn: func(ua string) string {
				return "fp-" + ua
			},
		}

		var capturedFingerprint string
		handler := Device(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedFingerprint = requestcontext.DeviceFingerprint(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		// Context with empty user agent
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := requestcontext.WithClientMetadata(req.Context(), "127.0.0.1", "")
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Empty(t, capturedFingerprint)
	})

	t.Run("skips fingerprint when FingerprintFn is nil", func(t *testing.T) {
		cfg := &DeviceConfig{
			FingerprintFn: nil,
		}

		var capturedFingerprint string
		handler := Device(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedFingerprint = requestcontext.DeviceFingerprint(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := requestcontext.WithClientMetadata(req.Context(), "127.0.0.1", "Mozilla/5.0")
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Empty(t, capturedFingerprint)
	})

	t.Run("extracts both device ID and fingerprint", func(t *testing.T) {
		cfg := &DeviceConfig{
			CookieName: "__Secure-Device-ID",
			FingerprintFn: func(ua string) string {
				return "fingerprint-hash"
			},
		}

		var capturedDeviceID, capturedFingerprint string
		handler := Device(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedDeviceID = requestcontext.DeviceID(r.Context())
			capturedFingerprint = requestcontext.DeviceFingerprint(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.AddCookie(&http.Cookie{Name: "__Secure-Device-ID", Value: "device-456"})
		ctx := requestcontext.WithClientMetadata(req.Context(), "127.0.0.1", "Chrome/120")
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, "device-456", capturedDeviceID)
		assert.Equal(t, "fingerprint-hash", capturedFingerprint)
	})

	t.Run("handles wrong cookie name gracefully", func(t *testing.T) {
		cfg := &DeviceConfig{
			CookieName: "__Secure-Device-ID",
		}

		var capturedDeviceID string
		handler := Device(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedDeviceID = requestcontext.DeviceID(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.AddCookie(&http.Cookie{Name: "wrong-cookie-name", Value: "device-123"})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Empty(t, capturedDeviceID)
	})
}

func TestContextHelpers(t *testing.T) {
	t.Run("DeviceID returns empty for fresh context", func(t *testing.T) {
		ctx := context.Background()
		assert.Empty(t, requestcontext.DeviceID(ctx))
	})

	t.Run("WithDeviceID and DeviceID roundtrip", func(t *testing.T) {
		ctx := context.Background()
		ctx = requestcontext.WithDeviceID(ctx, "test-device-id")
		assert.Equal(t, "test-device-id", requestcontext.DeviceID(ctx))
	})

	t.Run("DeviceFingerprint returns empty for fresh context", func(t *testing.T) {
		ctx := context.Background()
		assert.Empty(t, requestcontext.DeviceFingerprint(ctx))
	})

	t.Run("WithDeviceFingerprint and DeviceFingerprint roundtrip", func(t *testing.T) {
		ctx := context.Background()
		ctx = requestcontext.WithDeviceFingerprint(ctx, "test-fingerprint")
		assert.Equal(t, "test-fingerprint", requestcontext.DeviceFingerprint(ctx))
	})

	t.Run("device ID and fingerprint are independent", func(t *testing.T) {
		ctx := context.Background()
		ctx = requestcontext.WithDeviceID(ctx, "device-123")
		ctx = requestcontext.WithDeviceFingerprint(ctx, "fingerprint-456")

		assert.Equal(t, "device-123", requestcontext.DeviceID(ctx))
		assert.Equal(t, "fingerprint-456", requestcontext.DeviceFingerprint(ctx))
	})
}
