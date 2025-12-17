package handler

// Handler tests for consent module following Credo testing doctrine (AGENTS.md, testing.md).
//
// Per testing doctrine, these unit tests exist to verify:
// - HTTP status code mapping from domain errors (CodeUnauthorized -> 401, etc.)
// - Error response format consistency
// - Handler-level validation (query params, request body parsing)
//
// Happy-path behavior (200 OK responses) is tested via:
// - Primary: e2e/features/consent_flow.feature (Gherkin scenarios)
// - Secondary: internal/consent/integration_test.go

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	"credo/internal/consent/handler/mocks"
	consentModel "credo/internal/consent/models"
	"credo/internal/platform/middleware"
	dErrors "credo/pkg/domain-errors"
)

//go:generate mockgen -source=handler.go -destination=mocks/consent-mocks.go -package=mocks Service

type ConsentHandlerSuite struct {
	suite.Suite
	ctx context.Context
}

func (s *ConsentHandlerSuite) SetupSuite() {
	s.ctx = context.Background()
}

func TestConsentHandlerSuite(t *testing.T) {
	suite.Run(t, new(ConsentHandlerSuite))
}

// =============================================================================
// Grant Consent Tests - Error Mapping
// =============================================================================

// TestHandleGrantConsent_ErrorMapping verifies HTTP error mapping for grant endpoint.
// Reason not a feature test: Feature tests verify HTTP status codes via end-to-end requests;
// these tests verify handler-level error code mapping in isolation.
func (s *ConsentHandlerSuite) TestHandleGrantConsent_ErrorMapping() {
	s.T().Run("missing user context returns 500", func(t *testing.T) {
		// Handler extracts user from context; missing = internal error
		handler, _ := newTestHandler(t)
		req, err := newRequestWithBody(http.MethodPost, "/auth/consent",
			consentModel.GrantRequest{Purposes: []consentModel.Purpose{consentModel.PurposeLogin}}, "")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleGrantConsent(w, req)

		assertStatusAndError(t, w, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})

	s.T().Run("empty purposes array returns 400", func(t *testing.T) {
		handler, _ := newTestHandler(t)
		req, err := newRequestWithBody(http.MethodPost, "/auth/consent",
			consentModel.GrantRequest{Purposes: []consentModel.Purpose{}}, "user123")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleGrantConsent(w, req)

		assertStatusAndError(t, w, http.StatusBadRequest, "bad_request")
	})

	s.T().Run("invalid purpose value returns 400", func(t *testing.T) {
		handler, _ := newTestHandler(t)
		req, err := newRequestWithBody(http.MethodPost, "/auth/consent",
			consentModel.GrantRequest{Purposes: []consentModel.Purpose{"invalid_purpose"}}, "user123")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleGrantConsent(w, req)

		assertStatusAndError(t, w, http.StatusBadRequest, "bad_request")
	})

	s.T().Run("service CodeInternal error returns 500", func(t *testing.T) {
		handler, mockService := newTestHandler(t)
		mockService.EXPECT().Grant(
			gomock.Any(),
			"user123",
			[]consentModel.Purpose{consentModel.PurposeLogin},
		).Return(nil, dErrors.New(dErrors.CodeInternal, "storage system unavailable"))

		req, err := newRequestWithBody(http.MethodPost, "/auth/consent",
			consentModel.GrantRequest{Purposes: []consentModel.Purpose{consentModel.PurposeLogin}},
			"user123")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleGrantConsent(w, req)

		assertStatusAndError(t, w, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})
}

// =============================================================================
// Get Consents Tests - Error Mapping & Validation
// =============================================================================

// TestHandleGetConsents_ErrorMapping verifies HTTP error mapping for list endpoint.
func (s *ConsentHandlerSuite) TestHandleGetConsents_ErrorMapping() {
	s.T().Run("missing user context returns 500", func(t *testing.T) {
		handler, _ := newTestHandler(t)
		req := httptest.NewRequest(http.MethodGet, "/auth/consent", nil)
		w := httptest.NewRecorder()

		handler.handleGetConsents(w, req)

		assertStatusAndError(t, w, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})

	s.T().Run("service CodeInternal error returns 500", func(t *testing.T) {
		handler, mockService := newTestHandler(t)
		mockService.EXPECT().List(gomock.Any(), "user123", gomock.Any()).
			Return(nil, dErrors.New(dErrors.CodeInternal, "storage system unavailable"))

		req := httptest.NewRequest(http.MethodGet, "/auth/consent", nil)
		ctx := context.WithValue(req.Context(), middleware.ContextKeyUserID, "user123")
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		handler.handleGetConsents(w, req)

		assertStatusAndError(t, w, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})

	s.T().Run("invalid status filter returns 400", func(t *testing.T) {
		// Handler-level validation of query param
		handler, _ := newTestHandler(t)
		req := httptest.NewRequest(http.MethodGet, "/auth/consent?status=unknown", nil)
		ctx := context.WithValue(req.Context(), middleware.ContextKeyUserID, "user123")
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		handler.handleGetConsents(w, req)

		assertStatusAndError(t, w, http.StatusBadRequest, "bad_request")
	})
}

// =============================================================================
// Revoke Consent Tests - Error Mapping
// =============================================================================

// TestHandleRevokeConsent_ErrorMapping verifies HTTP error mapping for revoke endpoint.
func (s *ConsentHandlerSuite) TestHandleRevokeConsent_ErrorMapping() {
	s.T().Run("missing user context returns 500", func(t *testing.T) {
		handler, _ := newTestHandler(t)
		req, err := newRequestWithBody(http.MethodPost, "/auth/consent/revoke",
			consentModel.RevokeRequest{Purposes: []consentModel.Purpose{consentModel.PurposeLogin}}, "")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleRevokeConsent(w, req)

		assertStatusAndError(t, w, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})

	s.T().Run("empty purposes array returns 400", func(t *testing.T) {
		handler, _ := newTestHandler(t)
		req, err := newRequestWithBody(http.MethodPost, "/auth/consent/revoke",
			consentModel.RevokeRequest{Purposes: []consentModel.Purpose{}}, "user123")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleRevokeConsent(w, req)

		assertStatusAndError(t, w, http.StatusBadRequest, "bad_request")
	})

	s.T().Run("service CodeInternal error returns 500", func(t *testing.T) {
		handler, mockService := newTestHandler(t)
		mockService.EXPECT().Revoke(gomock.Any(), "user123", []consentModel.Purpose{consentModel.PurposeLogin}).
			Return(nil, dErrors.New(dErrors.CodeInternal, "storage system unavailable"))

		req, err := newRequestWithBody(http.MethodPost, "/auth/consent/revoke",
			consentModel.RevokeRequest{Purposes: []consentModel.Purpose{consentModel.PurposeLogin}}, "user123")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleRevokeConsent(w, req)

		assertStatusAndError(t, w, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})
}

// =============================================================================
// Test Helpers
// =============================================================================

func newTestHandler(t *testing.T) (*Handler, *mocks.MockService) {
	t.Helper()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	mockService := mocks.NewMockService(ctrl)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := New(mockService, logger, nil)
	r := chi.NewRouter()
	handler.Register(r)
	return handler, mockService
}

// newRequestWithBody creates an HTTP request with the given method, endpoint, and JSON body.
// If userID is not empty, it adds the userID to the request context.
func newRequestWithBody(method, endpoint string, body interface{}, userID string) (*http.Request, error) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req := httptest.NewRequest(method, endpoint, bytes.NewReader(bodyBytes))
	if userID != "" {
		ctx := context.WithValue(req.Context(), middleware.ContextKeyUserID, userID)
		req = req.WithContext(ctx)
	}
	return req, nil
}

// assertErrorResponse unmarshals the response body and asserts the error code.
func assertErrorResponse(t *testing.T, w *httptest.ResponseRecorder, expectedCode string) {
	t.Helper()
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, expectedCode, resp["error"])
}

// assertStatusAndError asserts both status code and error response in one call.
func assertStatusAndError(t *testing.T, w *httptest.ResponseRecorder, expectedStatus int, expectedCode string) {
	t.Helper()
	assert.Equal(t, expectedStatus, w.Code)
	assertErrorResponse(t, w, expectedCode)
}
