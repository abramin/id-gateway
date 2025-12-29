package request

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"credo/pkg/requestcontext"
)

func TestRequestID(t *testing.T) {
	t.Run("generates UUID when no header provided", func(t *testing.T) {
		var capturedID string
		handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedID = requestcontext.RequestID(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.NotEmpty(t, capturedID)
		assert.Len(t, capturedID, 36) // UUID format
		assert.Equal(t, capturedID, w.Header().Get("X-Request-ID"))
	})

	t.Run("accepts valid client-provided ID", func(t *testing.T) {
		var capturedID string
		handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedID = requestcontext.RequestID(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Request-ID", "my-request-123")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, "my-request-123", w.Header().Get("X-Request-ID"))
		assert.Equal(t, "my-request-123", capturedID)
	})

	t.Run("accepts ID with periods and underscores", func(t *testing.T) {
		handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Request-ID", "trace.span_1234")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, "trace.span_1234", w.Header().Get("X-Request-ID"))
	})

	t.Run("rejects ID exceeding max length", func(t *testing.T) {
		handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		longID := strings.Repeat("a", MaxRequestIDLength+1)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Request-ID", longID)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Should generate new UUID, not use the long one
		resultID := w.Header().Get("X-Request-ID")
		assert.NotEqual(t, longID, resultID)
		assert.Len(t, resultID, 36) // UUID format
	})

	t.Run("rejects ID with newline characters (log injection)", func(t *testing.T) {
		handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Request-ID", "valid\ninjected-log-line")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resultID := w.Header().Get("X-Request-ID")
		assert.NotContains(t, resultID, "\n")
		assert.Len(t, resultID, 36) // Generated UUID
	})

	t.Run("rejects ID with special characters", func(t *testing.T) {
		testCases := []struct {
			name string
			id   string
		}{
			{"spaces", "request id"},
			{"quotes", `request"id`},
			{"angle brackets", "request<id>"},
			{"semicolon", "request;id"},
			{"backslash", `request\id`},
			{"null byte", "request\x00id"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				}))

				req := httptest.NewRequest(http.MethodGet, "/test", nil)
				req.Header.Set("X-Request-ID", tc.id)
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)

				resultID := w.Header().Get("X-Request-ID")
				assert.NotEqual(t, tc.id, resultID, "should reject ID with %s", tc.name)
				assert.Len(t, resultID, 36) // Generated UUID
			})
		}
	})

	t.Run("accepts ID at exactly max length", func(t *testing.T) {
		handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		maxLengthID := strings.Repeat("a", MaxRequestIDLength)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Request-ID", maxLengthID)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, maxLengthID, w.Header().Get("X-Request-ID"))
	})
}

func TestIsValidRequestID(t *testing.T) {
	t.Run("valid IDs", func(t *testing.T) {
		validIDs := []string{
			"abc123",
			"ABC-123",
			"request_id_456",
			"trace.span.123",
			"a",
			strings.Repeat("x", MaxRequestIDLength),
		}

		for _, id := range validIDs {
			assert.True(t, isValidRequestID(id), "expected %q to be valid", id)
		}
	})

	t.Run("invalid IDs", func(t *testing.T) {
		invalidIDs := []string{
			"", // empty
			strings.Repeat("x", MaxRequestIDLength+1), // too long
			"has space",     // space
			"has\nnewline",  // newline
			"has\ttab",      // tab
			"has;semicolon", // semicolon
			"has<bracket>",  // brackets
			`has"quote`,     // quote
		}

		for _, id := range invalidIDs {
			assert.False(t, isValidRequestID(id), "expected %q to be invalid", id)
		}
	})
}

func TestRequestIDFromContext(t *testing.T) {
	t.Run("returns empty string when not set", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		assert.Equal(t, "", requestcontext.RequestID(req.Context()))
	})
}
