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

func (s *ConsentHandlerSuite) TestHandleGrantConsent() {
	handler, mockService := newTestHandler(s.T())
	grantTime := time.Date(2025, 12, 3, 10, 0, 0, 0, time.UTC)
	expiry := grantTime.Add(365 * 24 * time.Hour)
	mockService.EXPECT().Grant(
		gomock.Any(),
		"user123",
		[]consentModel.ConsentPurpose{consentModel.ConsentPurposeLogin},
	).Return([]*consentModel.ConsentRecord{{
		ID:        "consent_abc",
		Purpose:   consentModel.ConsentPurposeLogin,
		GrantedAt: grantTime,
		ExpiresAt: &expiry,
	}}, nil)

	body, err := json.Marshal(consentModel.GrantConsentRequest{Purposes: []consentModel.ConsentPurpose{consentModel.ConsentPurposeLogin}})
	require.NoError(s.T(), err)

	req := httptest.NewRequest(http.MethodPost, "/auth/consent", bytes.NewReader(body))
	ctx := context.WithValue(req.Context(), middleware.ContextKeyUserID, "user123")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.handleGrantConsent(w, req)

	assert.Equal(s.T(), http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(s.T(), json.Unmarshal(w.Body.Bytes(), &resp))
	granted := resp["granted"].([]any)
	grantedItem := granted[0].(map[string]any)
	assert.Equal(s.T(), "consent_abc", grantedItem["id"])
	assert.Equal(s.T(), "login", grantedItem["purpose"])
	assert.Equal(s.T(), "active", grantedItem["status"])
}

/*
func TestHandleRevokeConsent(t *testing.T) {
	revoked := false
	svc := stubService{
		revokeFn: func(ctx context.Context, userID string, purpose consentModel.ConsentPurpose) error {
			revoked = true
			assert.Equal(t, consentModel.ConsentPurposeRegistryCheck, purpose)
			return nil
		},
		grantFn: func(context.Context, string, []consentModel.ConsentPurpose) ([]*consentModel.ConsentRecord, error) {
			return nil, nil
		},
		listFn: func(context.Context, string) ([]*consentModel.ConsentRecord, error) { return nil, nil },
	}

	handler := newTestHandler(t, svc)
	body, err := json.Marshal(consentModel.RevokeConsentRequest{Purposes: []consentModel.ConsentPurpose{consentModel.ConsentPurposeRegistryCheck}})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/consent/revoke", bytes.NewReader(body))
	ctx := context.WithValue(req.Context(), middleware.ContextKeyUserID, "user123")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.handleRevokeConsent(w, req)

	assert.True(t, revoked)
	assert.Equal(t, http.StatusOK, w.Code)
}

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
