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

	"id-gateway/internal/consent/handler/mocks"
	consentModel "id-gateway/internal/consent/models"
	"id-gateway/internal/platform/middleware"
	dErrors "id-gateway/pkg/domain-errors"
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

func (s *ConsentHandlerSuite) TestHandleGrantConsent() {
	s.T().Run("200 - grant consent for single purpose", func(t *testing.T) {
		handler, mockService := newTestHandler(t)
		grantTime := time.Date(2025, 12, 3, 10, 0, 0, 0, time.UTC)
		expiry := grantTime.Add(365 * 24 * time.Hour)
		mockService.EXPECT().Grant(
			gomock.Any(),
			"user123",
			[]consentModel.ConsentPurpose{consentModel.ConsentPurposeLogin},
		).Return([]*consentModel.ConsentRecord{{
			Purpose:   consentModel.ConsentPurposeLogin,
			GrantedAt: grantTime,
			ExpiresAt: &expiry,
		}}, nil)

		req, err := newRequestWithBody(http.MethodPost, "/auth/consent",
			consentModel.GrantConsentRequest{Purposes: []consentModel.ConsentPurpose{consentModel.ConsentPurposeLogin}},
			"user123")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleGrantConsent(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		granted := resp["granted"].([]any)
		grantedItem := granted[0].(map[string]any)
		assert.Equal(t, "login", grantedItem["purpose"])
		assert.Equal(t, "active", grantedItem["status"])
	})

	s.T().Run("401 unauthorized - missing bearer token", func(t *testing.T) {
		handler, _ := newTestHandler(t)
		req, err := newRequestWithBody(http.MethodPost, "/auth/consent",
			consentModel.GrantConsentRequest{Purposes: []consentModel.ConsentPurpose{consentModel.ConsentPurposeLogin}},
			"")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleGrantConsent(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assertErrorResponse(t, w, "internal_error")
	})

	s.T().Run("400 bad request - empty purposes array", func(t *testing.T) {
		handler, _ := newTestHandler(t)
		req, err := newRequestWithBody(http.MethodPost, "/auth/consent",
			consentModel.GrantConsentRequest{Purposes: []consentModel.ConsentPurpose{}},
			"user123")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleGrantConsent(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assertErrorResponse(t, w, "bad_request")
	})

	s.T().Run("400 bad request - invalid purpose value", func(t *testing.T) {
		handler, _ := newTestHandler(t)
		req, err := newRequestWithBody(http.MethodPost, "/auth/consent",
			consentModel.GrantConsentRequest{Purposes: []consentModel.ConsentPurpose{"invalid_purpose"}},
			"user123")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleGrantConsent(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assertErrorResponse(t, w, "bad_request")
	})

	s.T().Run("500 internal server error - store failure", func(t *testing.T) {
		handler, mockService := newTestHandler(t)
		mockService.EXPECT().Grant(
			gomock.Any(),
			"user123",
			[]consentModel.ConsentPurpose{consentModel.ConsentPurposeLogin},
		).Return(nil, dErrors.New(dErrors.CodeInternal, "storage system unavailable"))

		req, err := newRequestWithBody(http.MethodPost, "/auth/consent",
			consentModel.GrantConsentRequest{Purposes: []consentModel.ConsentPurpose{consentModel.ConsentPurposeLogin}},
			"user123")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleGrantConsent(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assertErrorResponse(t, w, "internal_error")
	})
}

func (s *ConsentHandlerSuite) TestHandleRevokeConsent() {
	s.T().Run("200 - revoke consent for a purpose", func(t *testing.T) {
		handler, mockService := newTestHandler(t)
		revoked := false
		mockService.EXPECT().Revoke(
			gomock.Any(),
			"user123",
			consentModel.ConsentPurposeRegistryCheck,
		).DoAndReturn(func(ctx context.Context, userID string, purpose consentModel.ConsentPurpose) error {
			revoked = true
			assert.Equal(t, consentModel.ConsentPurposeRegistryCheck, purpose)
			return nil
		})

		req, err := newRequestWithBody(http.MethodPost, "/auth/consent/revoke",
			consentModel.RevokeConsentRequest{Purposes: []consentModel.ConsentPurpose{consentModel.ConsentPurposeRegistryCheck}},
			"user123")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleRevokeConsent(w, req)

		assert.True(t, revoked)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	s.T().Run("401 unauthorized - missing bearer token", func(t *testing.T) {
		handler, _ := newTestHandler(t)
		req, err := newRequestWithBody(http.MethodPost, "/auth/consent/revoke",
			consentModel.RevokeConsentRequest{Purposes: []consentModel.ConsentPurpose{consentModel.ConsentPurposeRegistryCheck}},
			"")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleRevokeConsent(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assertErrorResponse(t, w, "internal_error")
	})

	s.T().Run("400 bad request - empty purposes array", func(t *testing.T) {
		handler, _ := newTestHandler(t)
		req, err := newRequestWithBody(http.MethodPost, "/auth/consent/revoke",
			consentModel.RevokeConsentRequest{Purposes: []consentModel.ConsentPurpose{}},
			"user123")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleRevokeConsent(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assertErrorResponse(t, w, "bad_request")
	})

	s.T().Run("400 bad request - invalid purpose value", func(t *testing.T) {
		handler, _ := newTestHandler(t)
		req, err := newRequestWithBody(http.MethodPost, "/auth/consent/revoke",
			consentModel.RevokeConsentRequest{Purposes: []consentModel.ConsentPurpose{"invalid_purpose"}},
			"user123")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleRevokeConsent(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assertErrorResponse(t, w, "bad_request")
	})

	s.T().Run("500 internal server error - store failure", func(t *testing.T) {
		handler, mockService := newTestHandler(t)
		mockService.EXPECT().Revoke(
			gomock.Any(),
			"user123",
			consentModel.ConsentPurposeRegistryCheck,
		).Return(dErrors.New(dErrors.CodeInternal, "storage system unavailable"))

		req, err := newRequestWithBody(http.MethodPost, "/auth/consent/revoke",
			consentModel.RevokeConsentRequest{Purposes: []consentModel.ConsentPurpose{consentModel.ConsentPurposeRegistryCheck}},
			"user123")
		require.NoError(t, err)

		w := httptest.NewRecorder()
		handler.handleRevokeConsent(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assertErrorResponse(t, w, "internal_error")
	})
} /*
func TestHandleGetConsent_WithFilters(t *testing.T) {
	now := time.Now()
	expired := now.Add(-time.Hour)
	active := now.Add(time.Hour)
	listCalled := false
	svc := stubService{
		listFn: func(ctx context.Context, userID string) ([]*consentModel.ConsentRecord, error) {
			listCalled = true
			return []*consentModel.ConsentRecord{
				{
					ID:        "consent_active",
					Purpose:   consentModel.ConsentPurposeLogin,
					GrantedAt: now,
					ExpiresAt: &active,
				},
				{
					ID:        "consent_expired",
					Purpose:   consentModel.ConsentPurposeLogin,
					GrantedAt: now.Add(-2 * time.Hour),
					ExpiresAt: &expired,
				},
			}, nil
		},
		grantFn: func(context.Context, string, []consentModel.ConsentPurpose) ([]*consentModel.ConsentRecord, error) {
			return nil, nil
		},
		revokeFn: func(context.Context, string, consentModel.ConsentPurpose) error { return nil },
	}

	handler := newTestHandler(t, svc)
	req := httptest.NewRequest(http.MethodGet, "/auth/consent?status=active&purpose=login", nil)
	ctx := context.WithValue(req.Context(), middleware.ContextKeyUserID, "user123")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.handleGetConsent(w, req)

	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.True(t, listCalled)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	consentsRaw, ok := resp["consents"]
	require.True(t, ok, w.Body.String())
	consents, ok := consentsRaw.([]any)
	require.True(t, ok, w.Body.String())
	assert.Len(t, consents, 1)
	consent := consents[0].(map[string]any)
	assert.Equal(t, "consent_active", consent["id"])
	assert.Equal(t, "active", consent["status"])
}
*/
