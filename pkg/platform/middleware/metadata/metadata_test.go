package metadata

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMiddlewareHandler(t *testing.T) {
	tests := []struct {
		name           string
		headers        map[string]string
		remoteAddr     string
		trustedProxies []string
		expectedIP     string
		expectedUA     string
	}{
		{
			name: "extracts from RemoteAddr when no trusted proxies",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1",
				"User-Agent":      "Mozilla/5.0",
			},
			remoteAddr:     "192.168.1.1:12345",
			trustedProxies: nil,
			expectedIP:     "192.168.1.1",
			expectedUA:     "Mozilla/5.0",
		},
		{
			name: "trusts XFF when request from trusted proxy",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1",
				"User-Agent":      "curl/7.64.1",
			},
			remoteAddr:     "10.0.0.1:12345",
			trustedProxies: []string{"10.0.0.0/8"},
			expectedIP:     "203.0.113.1",
			expectedUA:     "curl/7.64.1",
		},
		{
			name: "falls back to RemoteAddr when no headers",
			headers: map[string]string{
				"User-Agent": "test-agent",
			},
			remoteAddr:     "192.168.1.100:54321",
			trustedProxies: nil,
			expectedIP:     "192.168.1.100",
			expectedUA:     "test-agent",
		},
		{
			name:           "handles missing user agent",
			headers:        map[string]string{},
			remoteAddr:     "10.0.0.1:8080",
			trustedProxies: nil,
			expectedIP:     "10.0.0.1",
			expectedUA:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedCtx context.Context
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedCtx = r.Context()
				w.WriteHeader(http.StatusOK)
			})

			var prefixes []netip.Prefix
			for _, cidr := range tt.trustedProxies {
				prefix, _ := netip.ParsePrefix(cidr)
				prefixes = append(prefixes, prefix)
			}
			cfg := &Config{TrustedProxies: prefixes}
			mw := NewMiddleware(cfg)
			handler := mw.Handler(testHandler)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedIP, GetClientIP(capturedCtx), "IP address mismatch")
			assert.Equal(t, tt.expectedUA, GetUserAgent(capturedCtx), "User-Agent mismatch")
		})
	}
}

func TestGetClientIPFromContext(t *testing.T) {
	t.Run("returns empty string for context without IP", func(t *testing.T) {
		ctx := context.Background()
		assert.Equal(t, "", GetClientIP(ctx))
	})

	t.Run("returns IP from context", func(t *testing.T) {
		ctx := WithClientMetadata(context.Background(), "192.168.1.1", "test-agent")
		assert.Equal(t, "192.168.1.1", GetClientIP(ctx))
	})
}

func TestGetUserAgentFromContext(t *testing.T) {
	t.Run("returns empty string for context without UA", func(t *testing.T) {
		ctx := context.Background()
		assert.Equal(t, "", GetUserAgent(ctx))
	})

	t.Run("returns UA from context", func(t *testing.T) {
		ctx := WithClientMetadata(context.Background(), "192.168.1.1", "Mozilla/5.0")
		assert.Equal(t, "Mozilla/5.0", GetUserAgent(ctx))
	})
}
