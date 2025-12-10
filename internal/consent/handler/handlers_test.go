package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func (s *ConsentHandlerSuite) TestHandleGrantConsent() {
	s.T().Run("200 - grant consent for single purpose", func(t *testing.T) {
		handler, mockService := newTestHandler(t)
		grantTime := time.Date(2025, 12, 3, 10, 0, 0, 0, time.UTC)
		expiry := grantTime.Add(365 * 24 * time.Hour)

		mockService.EXPECT().Grant(
			gomock.Any(),
			"user123",
			[]consentModel.Purpose{consentModel.PurposeLogin},
		).Return([]*consentModel.Record{{
			Purpose:   consentModel.PurposeLogin,
			GrantedAt: grantTime,
			ExpiresAt: &expiry,
		}}, nil)

		req, err := newRequestWithBody(http.MethodPost, "/auth/consent",
			consentModel.GrantRequest{Purposes: []consentModel.Purpose{consentModel.PurposeLogin}},
			"user123")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleGrantConsent(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp consentModel.GrantResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		granted := resp.Granted[0]
		assert.Equal(t, consentModel.PurposeLogin, granted.Purpose)
		assert.Equal(t, consentModel.StatusActive, granted.Status)
		assert.Equal(t, grantTime, granted.GrantedAt)
		assert.Equal(t, expiry, *granted.ExpiresAt)
	})

	s.T().Run("401 unauthorized - missing bearer token", func(t *testing.T) {
		handler, _ := newTestHandler(t)
		req, err := newRequestWithBody(http.MethodPost, "/auth/consent",
			consentModel.GrantRequest{Purposes: []consentModel.Purpose{consentModel.PurposeLogin}},
			"")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleGrantConsent(w, req)

		assertStatusAndError(t, w, http.StatusInternalServerError, "internal_error")
	})

	s.T().Run("400 bad request - empty purposes array", func(t *testing.T) {
		handler, _ := newTestHandler(t)
		req, err := newRequestWithBody(http.MethodPost, "/auth/consent",
			consentModel.GrantRequest{Purposes: []consentModel.Purpose{}},
			"user123")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleGrantConsent(w, req)

		assertStatusAndError(t, w, http.StatusBadRequest, "bad_request")
	})

	s.T().Run("400 bad request - invalid purpose value", func(t *testing.T) {
		handler, _ := newTestHandler(t)
		req, err := newRequestWithBody(http.MethodPost, "/auth/consent",
			consentModel.GrantRequest{Purposes: []consentModel.Purpose{"invalid_purpose"}},
			"user123")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleGrantConsent(w, req)

		assertStatusAndError(t, w, http.StatusBadRequest, "bad_request")
	})

	s.T().Run("500 internal server error - store failure", func(t *testing.T) {
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

		assertStatusAndError(t, w, http.StatusInternalServerError, "internal_error")
	})
}

func (s *ConsentHandlerSuite) TestHandleGetConsent_WithFilters() {
	s.T().Run("200 - get consent records with no filter", func(t *testing.T) {
		handler, mockService := newTestHandler(t)
		mockService.EXPECT().List(
			gomock.Any(),
			"user123",
			gomock.Any(),
		).Return([]*consentModel.ConsentWithStatus{
			newMockRecord(consentModel.PurposeLogin, consentModel.StatusActive, nil),
			newMockRecord(consentModel.PurposeRegistryCheck, consentModel.StatusRevoked, ptrTime(time.Date(2025, 3, 1, 10, 0, 0, 0, time.UTC))),
		}, nil)

		req, err := newRequestWithBody(http.MethodGet, "/auth/consent", nil, "user123")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleGetConsents(w, req)

		var resp consentModel.ListResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, 2, len(resp.Consents))
		assert.Equal(t, consentModel.PurposeLogin, resp.Consents[0].Purpose)
		assert.Equal(t, consentModel.StatusActive, resp.Consents[0].Status)
		assert.Equal(t, consentModel.PurposeRegistryCheck, resp.Consents[1].Purpose)
		assert.Equal(t, consentModel.StatusRevoked, resp.Consents[1].Status)
		assert.NotNil(t, resp.Consents[1].RevokedAt)
	})

	s.T().Run("200 - get consent records with filter", func(t *testing.T) {
		handler, mockService := newTestHandler(t)
		mockService.EXPECT().List(
			gomock.Any(),
			"user123",
			&consentModel.RecordFilter{
				Purpose: string(consentModel.PurposeLogin),
				Status:  string(consentModel.StatusActive),
			},
		).Return([]*consentModel.ConsentWithStatus{
			newMockRecord(consentModel.PurposeLogin, consentModel.StatusActive, nil),
		}, nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/consent?purpose=login&status=active", nil)
		ctx := context.WithValue(req.Context(), middleware.ContextKeyUserID, "user123")
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handler.handleGetConsents(w, req)

		var resp consentModel.ListResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, 1, len(resp.Consents))
		assert.Equal(t, consentModel.PurposeLogin, resp.Consents[0].Purpose)
		assert.Equal(t, consentModel.StatusActive, resp.Consents[0].Status)
	})

	s.T().Run("401 unauthorized - missing bearer token", func(t *testing.T) {
		handler, _ := newTestHandler(t)
		req := httptest.NewRequest(http.MethodGet, "/auth/consent", nil)

		w := httptest.NewRecorder()
		handler.handleGetConsents(w, req)

		assertStatusAndError(t, w, http.StatusInternalServerError, "internal_error")
	})

	s.T().Run("500 internal server error - store failure", func(t *testing.T) {
		handler, mockService := newTestHandler(t)
		mockService.EXPECT().List(
			gomock.Any(),
			"user123",
			gomock.Any(),
		).Return(nil, dErrors.New(dErrors.CodeInternal, "storage system unavailable"))

		req := httptest.NewRequest(http.MethodGet, "/auth/consent", nil)
		ctx := context.WithValue(req.Context(), middleware.ContextKeyUserID, "user123")
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handler.handleGetConsents(w, req)

		assertStatusAndError(t, w, http.StatusInternalServerError, "internal_error")
	})

	s.T().Run("400 bad request - invalid status filter", func(t *testing.T) {
		handler, _ := newTestHandler(t)
		req := httptest.NewRequest(http.MethodGet, "/auth/consent?status=unknown", nil)
		ctx := context.WithValue(req.Context(), middleware.ContextKeyUserID, "user123")
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handler.handleGetConsents(w, req)

		assertStatusAndError(t, w, http.StatusBadRequest, "bad_request")
	})
}

func (s *ConsentHandlerSuite) TestHandleRevokeConsent() {
	s.T().Run("200 - revoke consent", func(t *testing.T) {
		handler, mockService := newTestHandler(t)
		mockService.EXPECT().Revoke(
			gomock.Any(),
			"user123",
			[]consentModel.Purpose{consentModel.PurposeLogin},
		).Return([]*consentModel.Record{{
			ID:        "consent_login",
			Purpose:   consentModel.PurposeLogin,
			GrantedAt: time.Now(),
			RevokedAt: ptrTime(time.Now()),
		}}, nil)

		req, err := newRequestWithBody(http.MethodPost, "/auth/consent/revoke",
			consentModel.RevokeRequest{Purposes: []consentModel.Purpose{consentModel.PurposeLogin}},
			"user123")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleRevokeConsent(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp consentModel.RevokeResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Len(t, resp.Revoked, 1)
	})

	s.T().Run("401 unauthorized - missing bearer token", func(t *testing.T) {
		handler, _ := newTestHandler(t)
		req, err := newRequestWithBody(http.MethodPost, "/auth/consent/revoke",
			consentModel.RevokeRequest{Purposes: []consentModel.Purpose{consentModel.PurposeLogin}},
			"")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleRevokeConsent(w, req)

		assertStatusAndError(t, w, http.StatusInternalServerError, "internal_error")
	})

	s.T().Run("400 bad request - empty purposes array", func(t *testing.T) {
		handler, _ := newTestHandler(t)
		req, err := newRequestWithBody(http.MethodPost, "/auth/consent/revoke",
			consentModel.RevokeRequest{Purposes: []consentModel.Purpose{}},
			"user123")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleRevokeConsent(w, req)

		assertStatusAndError(t, w, http.StatusBadRequest, "bad_request")
	})

	s.T().Run("500 internal server error - store failure", func(t *testing.T) {
		handler, mockService := newTestHandler(t)
		mockService.EXPECT().Revoke(
			gomock.Any(),
			"user123",
			[]consentModel.Purpose{consentModel.PurposeLogin},
		).Return(nil, dErrors.New(dErrors.CodeInternal, "storage system unavailable"))

		req, err := newRequestWithBody(http.MethodPost, "/auth/consent/revoke",
			consentModel.RevokeRequest{Purposes: []consentModel.Purpose{consentModel.PurposeLogin}},
			"user123")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleRevokeConsent(w, req)

		assertStatusAndError(t, w, http.StatusInternalServerError, "internal_error")
	})
}

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

// newMockRecord creates a ConsentWithStatus for testing.
func newMockRecord(purpose consentModel.Purpose, status consentModel.Status, revokedAt *time.Time) *consentModel.ConsentWithStatus {
	grantedAt := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	expiresAt := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	return &consentModel.ConsentWithStatus{
		Consent: consentModel.Consent{
			ID:        "consent_" + string(purpose),
			Purpose:   purpose,
			GrantedAt: grantedAt,
			ExpiresAt: ptrTime(expiresAt),
			RevokedAt: revokedAt,
		},
		Status: status,
	}
}
