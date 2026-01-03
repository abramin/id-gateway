package httputil

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	dErrors "credo/pkg/domain-errors"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testRequest is a simple test struct for JSON decoding
type testRequest struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

// validatingRequest implements Validatable
type validatingRequest struct {
	Name string `json:"name"`
}

func (r *validatingRequest) Validate() error {
	if r.Name == "" {
		return errors.New("name is required")
	}
	return nil
}

// fullRequest implements all preparation interfaces
type fullRequest struct {
	Name      string `json:"name"`
	sanitized bool
	validated bool
}

func (r *fullRequest) Sanitize() {
	r.sanitized = true
}

func (r *fullRequest) Normalize() {
	// no-op for testing
}

func (r *fullRequest) Validate() error {
	r.validated = true
	if r.Name == "" {
		return errors.New("name is required")
	}
	return nil
}

func TestDecodeJSON(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctx := context.Background()

	t.Run("successful decode", func(t *testing.T) {
		body := `{"name":"test","value":42}`
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
		w := httptest.NewRecorder()

		result, ok := DecodeJSON[testRequest](w, req, logger, ctx, "test-request-id")

		assert.True(t, ok)
		require.NotNil(t, result)
		assert.Equal(t, "test", result.Name)
		assert.Equal(t, 42, result.Value)
	})

	t.Run("invalid JSON returns error", func(t *testing.T) {
		body := `{invalid json}`
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
		w := httptest.NewRecorder()

		result, ok := DecodeJSON[testRequest](w, req, logger, ctx, "test-request-id")

		assert.False(t, ok)
		assert.Nil(t, result)
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var errResp map[string]string
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &errResp))
		assert.Equal(t, "bad_request", errResp["error"])
	})

	t.Run("empty body returns error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(""))
		w := httptest.NewRecorder()

		result, ok := DecodeJSON[testRequest](w, req, logger, ctx, "test-request-id")

		assert.False(t, ok)
		assert.Nil(t, result)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestDecodeAndPrepare(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctx := context.Background()

	t.Run("successful decode and validate", func(t *testing.T) {
		body := `{"name":"test"}`
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
		w := httptest.NewRecorder()

		result, ok := DecodeAndPrepare[validatingRequest](w, req, logger, ctx, "test-request-id")

		assert.True(t, ok)
		require.NotNil(t, result)
		assert.Equal(t, "test", result.Name)
	})

	t.Run("validation failure returns error", func(t *testing.T) {
		body := `{"name":""}`
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
		w := httptest.NewRecorder()

		result, ok := DecodeAndPrepare[validatingRequest](w, req, logger, ctx, "test-request-id")

		assert.False(t, ok)
		assert.Nil(t, result)
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var errResp map[string]string
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &errResp))
		assert.Contains(t, errResp["error_description"], "name is required")
	})

	t.Run("calls all preparation methods", func(t *testing.T) {
		body := `{"name":"test"}`
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
		w := httptest.NewRecorder()

		result, ok := DecodeAndPrepare[fullRequest](w, req, logger, ctx, "test-request-id")

		assert.True(t, ok)
		require.NotNil(t, result)
		assert.True(t, result.sanitized, "Sanitize() should have been called")
		assert.True(t, result.validated, "Validate() should have been called")
	})
}

func TestPrepareRequest(t *testing.T) {
	t.Run("calls validation", func(t *testing.T) {
		req := &validatingRequest{Name: "test"}
		err := PrepareRequest(req)
		assert.NoError(t, err)
	})

	t.Run("returns validation error", func(t *testing.T) {
		req := &validatingRequest{Name: ""}
		err := PrepareRequest(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "name is required")
	})

	t.Run("handles non-validatable types", func(t *testing.T) {
		req := &testRequest{Name: "test"}
		err := PrepareRequest(req)
		assert.NoError(t, err)
	})
}

// domainErrorRequest returns a domain error from Validate()
type domainErrorRequest struct {
	ID string `json:"id"`
}

func (r *domainErrorRequest) Validate() error {
	if r.ID == "" {
		return dErrors.New(dErrors.CodeBadRequest, "id is required")
	}
	return nil
}

func TestDecodeAndPrepare_PreservesDomainError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctx := context.Background()

	t.Run("preserves domain error code from Validate", func(t *testing.T) {
		body := `{"id":""}`
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
		w := httptest.NewRecorder()

		result, ok := DecodeAndPrepare[domainErrorRequest](w, req, logger, ctx, "test-request-id")

		assert.False(t, ok)
		assert.Nil(t, result)
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var errResp map[string]string
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &errResp))
		// Domain error with CodeBadRequest should map to "bad_request", not "validation_error"
		assert.Equal(t, "bad_request", errResp["error"])
		assert.Contains(t, errResp["error_description"], "id is required")
	})

	t.Run("wraps plain error with validation code", func(t *testing.T) {
		body := `{"name":""}`
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
		w := httptest.NewRecorder()

		result, ok := DecodeAndPrepare[validatingRequest](w, req, logger, ctx, "test-request-id")

		assert.False(t, ok)
		assert.Nil(t, result)
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var errResp map[string]string
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &errResp))
		// Plain error should be wrapped with CodeValidation -> "validation_error"
		assert.Equal(t, "validation_error", errResp["error"])
	})
}
