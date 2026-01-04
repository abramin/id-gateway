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

	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	"credo/internal/consent/handler/mocks"
	consentModel "credo/internal/consent/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/requestcontext"
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
	s.Run("missing user context returns 500", func() {
		// Handler extracts user from context; missing = internal error
		handler, _ := newTestHandler(s.T())
		req, err := newRequestWithBody(http.MethodPost, "/auth/consent",
			GrantRequest{Purposes: []string{consentModel.PurposeLogin.String()}}, "")
		s.Require().NoError(err)

		w := httptest.NewRecorder()
		handler.HandleGrantConsent(w, req)

		s.assertStatusAndError(w, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})

	s.Run("empty purposes array returns 400", func() {
		handler, _ := newTestHandler(s.T())
		req, err := newRequestWithBody(http.MethodPost, "/auth/consent",
			GrantRequest{Purposes: []string{}}, "550e8400-e29b-41d4-a716-446655440000")
		s.Require().NoError(err)

		w := httptest.NewRecorder()
		handler.HandleGrantConsent(w, req)

		s.assertStatusAndError(w, http.StatusBadRequest, "validation_error")
	})

	s.Run("invalid purpose value returns 400", func() {
		handler, _ := newTestHandler(s.T())
		req, err := newRequestWithBody(http.MethodPost, "/auth/consent",
			GrantRequest{Purposes: []string{"invalid_purpose"}}, "550e8400-e29b-41d4-a716-446655440000")
		s.Require().NoError(err)

		w := httptest.NewRecorder()
		handler.HandleGrantConsent(w, req)

		s.assertStatusAndError(w, http.StatusBadRequest, "validation_error")
	})

	s.Run("service CodeInternal error returns 500", func() {
		handler, mockService := newTestHandler(s.T())
		testUserIDStr := "550e8400-e29b-41d4-a716-446655440000"
		userID, _ := id.ParseUserID(testUserIDStr)
		mockService.EXPECT().Grant(
			gomock.Any(),
			userID,
			[]consentModel.Purpose{consentModel.PurposeLogin},
		).Return(nil, dErrors.New(dErrors.CodeInternal, "storage system unavailable"))

		req, err := newRequestWithBody(http.MethodPost, "/auth/consent",
			GrantRequest{Purposes: []string{consentModel.PurposeLogin.String()}},
			testUserIDStr)
		s.Require().NoError(err)

		w := httptest.NewRecorder()
		handler.HandleGrantConsent(w, req)

		s.assertStatusAndError(w, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})
}

// =============================================================================
// Get Consents Tests - Error Mapping & Validation
// =============================================================================

// TestHandleGetConsents_ErrorMapping verifies HTTP error mapping for list endpoint.
func (s *ConsentHandlerSuite) TestHandleGetConsents_ErrorMapping() {
	s.Run("missing user context returns 500", func() {
		handler, _ := newTestHandler(s.T())
		req := httptest.NewRequest(http.MethodGet, "/auth/consent", nil)
		w := httptest.NewRecorder()

		handler.HandleGetConsents(w, req)

		s.assertStatusAndError(w, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})

	s.Run("service CodeInternal error returns 500", func() {
		handler, mockService := newTestHandler(s.T())
		testUserIDStr := "550e8400-e29b-41d4-a716-446655440000"
		userID, _ := id.ParseUserID(testUserIDStr)
		mockService.EXPECT().List(gomock.Any(), userID, gomock.Any()).
			Return(nil, dErrors.New(dErrors.CodeInternal, "storage system unavailable"))

		req := httptest.NewRequest(http.MethodGet, "/auth/consent", nil)
		ctx := requestcontext.WithUserID(req.Context(), userID)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		handler.HandleGetConsents(w, req)

		s.assertStatusAndError(w, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})

	s.Run("invalid status filter returns 400", func() {
		// Handler-level validation of query param
		handler, _ := newTestHandler(s.T())
		userID, _ := id.ParseUserID("550e8400-e29b-41d4-a716-446655440000")
		req := httptest.NewRequest(http.MethodGet, "/auth/consent?status=unknown", nil)
		ctx := requestcontext.WithUserID(req.Context(), userID)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		handler.HandleGetConsents(w, req)

		s.assertStatusAndError(w, http.StatusBadRequest, "validation_error")
	})
}

// =============================================================================
// Revoke Consent Tests - Error Mapping
// =============================================================================

// TestHandleRevokeConsent_ErrorMapping verifies HTTP error mapping for revoke endpoint.
func (s *ConsentHandlerSuite) TestHandleRevokeConsent_ErrorMapping() {
	s.Run("missing user context returns 500", func() {
		handler, _ := newTestHandler(s.T())
		req, err := newRequestWithBody(http.MethodPost, "/auth/consent/revoke",
			RevokeRequest{Purposes: []string{consentModel.PurposeLogin.String()}}, "")
		s.Require().NoError(err)

		w := httptest.NewRecorder()
		handler.HandleRevokeConsent(w, req)

		s.assertStatusAndError(w, http.StatusInternalServerError, string(dErrors.CodeInternal))
	})

	s.Run("empty purposes array returns 400", func() {
		handler, _ := newTestHandler(s.T())
		req, err := newRequestWithBody(http.MethodPost, "/auth/consent/revoke",
			RevokeRequest{Purposes: []string{}}, "550e8400-e29b-41d4-a716-446655440000")
		s.Require().NoError(err)

		w := httptest.NewRecorder()
		handler.HandleRevokeConsent(w, req)

		s.assertStatusAndError(w, http.StatusBadRequest, "validation_error")
	})

	s.Run("service CodeInternal error returns 500", func() {
		handler, mockService := newTestHandler(s.T())
		testUserIDStr := "550e8400-e29b-41d4-a716-446655440000"
		userID, _ := id.ParseUserID(testUserIDStr)
		mockService.EXPECT().Revoke(gomock.Any(), userID, []consentModel.Purpose{consentModel.PurposeLogin}).
			Return(nil, dErrors.New(dErrors.CodeInternal, "storage system unavailable"))

		req, err := newRequestWithBody(http.MethodPost, "/auth/consent/revoke",
			RevokeRequest{Purposes: []string{consentModel.PurposeLogin.String()}}, testUserIDStr)
		s.Require().NoError(err)

		w := httptest.NewRecorder()
		handler.HandleRevokeConsent(w, req)

		s.assertStatusAndError(w, http.StatusInternalServerError, string(dErrors.CodeInternal))
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
	return handler, mockService
}

// newRequestWithBody creates an HTTP request with the given method, endpoint, and JSON body.
// If userID is not empty and valid, it adds the typed userID to the request context.
func newRequestWithBody(method, endpoint string, body interface{}, userID string) (*http.Request, error) { //nolint:unparam // test helper designed for any method
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req := httptest.NewRequest(method, endpoint, bytes.NewReader(bodyBytes))
	if userID != "" {
		if parsedUserID, parseErr := id.ParseUserID(userID); parseErr == nil {
			ctx := requestcontext.WithUserID(req.Context(), parsedUserID)
			req = req.WithContext(ctx)
		}
	}
	return req, nil
}

// assertErrorResponse unmarshals the response body and asserts the error code.
func (s *ConsentHandlerSuite) assertErrorResponse(w *httptest.ResponseRecorder, expectedCode string) {
	var resp map[string]any
	s.Require().NoError(json.Unmarshal(w.Body.Bytes(), &resp))
	s.Assert().Equal(expectedCode, resp["error"])
}

// assertStatusAndError asserts both status code and error response in one call.
func (s *ConsentHandlerSuite) assertStatusAndError(w *httptest.ResponseRecorder, expectedStatus int, expectedCode string) {
	s.Assert().Equal(expectedStatus, w.Code)
	s.assertErrorResponse(w, expectedCode)
}
