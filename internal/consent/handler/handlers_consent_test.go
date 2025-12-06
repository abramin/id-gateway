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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	consentModel "id-gateway/internal/consent/models"
	"id-gateway/internal/platform/middleware"
)

type stubService struct {
	grantFn  func(ctx context.Context, userID string, purposes []consentModel.ConsentPurpose) ([]*consentModel.ConsentRecord, error)
	revokeFn func(ctx context.Context, userID string, purpose consentModel.ConsentPurpose) error
	listFn   func(ctx context.Context, userID string) ([]*consentModel.ConsentRecord, error)
}

func (s stubService) Grant(ctx context.Context, userID string, purposes []consentModel.ConsentPurpose) ([]*consentModel.ConsentRecord, error) {
	return s.grantFn(ctx, userID, purposes)
}

func (s stubService) Revoke(ctx context.Context, userID string, purpose consentModel.ConsentPurpose) error {
	return s.revokeFn(ctx, userID, purpose)
}

func (s stubService) Require(context.Context, string, consentModel.ConsentPurpose) error {
	return nil
}

func (s stubService) List(ctx context.Context, userID string) ([]*consentModel.ConsentRecord, error) {
	return s.listFn(ctx, userID)
}

func newTestHandler(t *testing.T, svc Service) *Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(svc, logger, nil)
}

func TestHandleGrantConsent(t *testing.T) {
	grantTime := time.Date(2025, 12, 3, 10, 0, 0, 0, time.UTC)
	expiry := grantTime.Add(365 * 24 * time.Hour)
	svc := stubService{
		grantFn: func(ctx context.Context, userID string, purposes []consentModel.ConsentPurpose) ([]*consentModel.ConsentRecord, error) {
			assert.Equal(t, "user123", userID)
			assert.Equal(t, []consentModel.ConsentPurpose{consentModel.ConsentPurposeLogin}, purposes)
			return []*consentModel.ConsentRecord{{
				ID:        "consent_abc",
				Purpose:   consentModel.ConsentPurposeLogin,
				GrantedAt: grantTime,
				ExpiresAt: &expiry,
			}}, nil
		},
	}

	handler := newTestHandler(t, svc)
	body, err := json.Marshal(consentModel.GrantConsentRequest{Purposes: []consentModel.ConsentPurpose{consentModel.ConsentPurposeLogin}})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/consent", bytes.NewReader(body))
	ctx := context.WithValue(req.Context(), middleware.ContextKeyUserID, "user123")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.handleGrantConsent(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	granted := resp["granted"].([]any)
	grantedItem := granted[0].(map[string]any)
	assert.Equal(t, "consent_abc", grantedItem["id"])
	assert.Equal(t, "login", grantedItem["purpose"])
	assert.Equal(t, "active", grantedItem["status"])
}

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
