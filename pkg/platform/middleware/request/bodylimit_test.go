package request

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBodyLimit(t *testing.T) {
	t.Run("request under limit passes through", func(t *testing.T) {
		const maxBytes int64 = 1024
		body := strings.Repeat("x", 100) // 100 bytes

		handler := BodyLimit(maxBytes)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			assert.Len(t, data, 100)
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("request at exact limit passes through", func(t *testing.T) {
		const maxBytes int64 = 100
		body := strings.Repeat("x", 100) // exactly 100 bytes

		handler := BodyLimit(maxBytes)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			assert.Len(t, data, 100)
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("request over limit returns error on read", func(t *testing.T) {
		const maxBytes int64 = 100
		body := strings.Repeat("x", 200) // 200 bytes, over limit

		var readErr error
		handler := BodyLimit(maxBytes)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, readErr = io.ReadAll(r.Body)
			// MaxBytesReader returns an error when attempting to read beyond the limit
		}))

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		require.Error(t, readErr)
		assert.Contains(t, readErr.Error(), "request body too large")
	})

	t.Run("empty body passes through", func(t *testing.T) {
		const maxBytes int64 = 1024

		handler := BodyLimit(maxBytes)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			assert.Empty(t, data)
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("GET request with no body passes through", func(t *testing.T) {
		const maxBytes int64 = 1024

		handler := BodyLimit(maxBytes)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("chunked body over limit returns error", func(t *testing.T) {
		const maxBytes int64 = 100
		// Create a reader that will return more bytes than allowed
		body := bytes.NewReader([]byte(strings.Repeat("x", 200)))

		var readErr error
		handler := BodyLimit(maxBytes)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, readErr = io.ReadAll(r.Body)
		}))

		req := httptest.NewRequest(http.MethodPost, "/test", body)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		require.Error(t, readErr)
	})
}
