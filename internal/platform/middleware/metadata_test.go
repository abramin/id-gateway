package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientMetadata(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expectedIP string
		expectedUA string
	}{
		{
			name: "extracts from X-Forwarded-For",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1, 198.51.100.1",
				"User-Agent":      "Mozilla/5.0",
			},
			remoteAddr: "192.168.1.1:12345",
			expectedIP: "203.0.113.1",
			expectedUA: "Mozilla/5.0",
		},
		{
			name: "extracts from X-Real-IP when no X-Forwarded-For",
			headers: map[string]string{
				"X-Real-IP":  "203.0.113.2",
				"User-Agent": "curl/7.64.1",
			},
			remoteAddr: "192.168.1.1:12345",
			expectedIP: "203.0.113.2",
			expectedUA: "curl/7.64.1",
		},
		{
			name: "falls back to RemoteAddr",
			headers: map[string]string{
				"User-Agent": "test-agent",
			},
			remoteAddr: "192.168.1.100:54321",
			expectedIP: "192.168.1.100",
			expectedUA: "test-agent",
		},
		{
			name:       "handles missing user agent",
			headers:    map[string]string{},
			remoteAddr: "10.0.0.1:8080",
			expectedIP: "10.0.0.1",
			expectedUA: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test handler that captures the context
			var capturedCtx context.Context
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedCtx = r.Context()
				w.WriteHeader(http.StatusOK)
			})

			// Wrap with ClientMetadata middleware
			handler := ClientMetadata(testHandler)

			// Create test request
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Execute request
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			// Verify context values
			assert.Equal(t, tt.expectedIP, GetClientIP(capturedCtx), "IP address mismatch")
			assert.Equal(t, tt.expectedUA, GetUserAgent(capturedCtx), "User-Agent mismatch")
		})
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expectedIP string
	}{
		{
			name: "single IP in X-Forwarded-For",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1",
			},
			remoteAddr: "192.168.1.1:12345",
			expectedIP: "203.0.113.1",
		},
		{
			name: "multiple IPs in X-Forwarded-For",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1, 198.51.100.1, 192.0.2.1",
			},
			remoteAddr: "192.168.1.1:12345",
			expectedIP: "203.0.113.1",
		},
		{
			name: "X-Real-IP takes precedence over RemoteAddr",
			headers: map[string]string{
				"X-Real-IP": "203.0.113.2",
			},
			remoteAddr: "192.168.1.1:12345",
			expectedIP: "203.0.113.2",
		},
		{
			name:       "IPv4 RemoteAddr",
			headers:    map[string]string{},
			remoteAddr: "192.168.1.100:54321",
			expectedIP: "192.168.1.100",
		},
		{
			name:       "IPv6 RemoteAddr",
			headers:    map[string]string{},
			remoteAddr: "[::1]:8080",
			expectedIP: "[::1]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			ip := getClientIP(req)
			assert.Equal(t, tt.expectedIP, ip)
		})
	}
}
