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

	"id-gateway/internal/audit"
	"id-gateway/internal/consent/handler"
	consentModel "id-gateway/internal/consent/models"
	"id-gateway/internal/consent/service"
	"id-gateway/internal/consent/store"
	"id-gateway/internal/platform/middleware"
)

func TestConsentIntegrationFlow(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	consentStore := store.NewInMemoryStore()
	auditStore := audit.NewInMemoryStore()
	svc := service.NewService(consentStore, audit.NewPublisher(auditStore), logger, 365*24*time.Hour)
	handler := handler.New(svc, logger, nil)

	router := chi.NewRouter()
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), middleware.ContextKeyUserID, "user123")
			ctx = context.WithValue(ctx, middleware.ContextKeySessionID, "session123")
			ctx = context.WithValue(ctx, middleware.ContextKeyClientID, "client123")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	handler.Register(router)

	server := httptest.NewServer(router)
	defer server.Close()

	t.Log("Step 1: Grant consent for multiple purposes")
	grantBody, _ := json.Marshal(map[string]any{"purposes": []string{"login", "registry_check", "profile_access"}})
	resp, err := http.Post(server.URL+"/auth/consent", "application/json", bytes.NewReader(grantBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	grantRespBody, _ := io.ReadAll(resp.Body)
	var grantData consentModel.GrantResponse
	require.NoError(t, json.Unmarshal(grantRespBody, &grantData))
	assert.Len(t, grantData.Granted, 3)
	assert.Contains(t, grantData.Message, "Consent granted for 3 purposes")
	for _, g := range grantData.Granted {
		assert.Equal(t, consentModel.StatusActive, g.Status)
		assert.NotNil(t, g.ExpiresAt)
	}

	t.Log("Step 2: List consents and verify all are active")
	listResp, err := http.Get(server.URL + "/auth/consent")
	require.NoError(t, err)
	defer listResp.Body.Close()
	assert.Equal(t, http.StatusOK, listResp.StatusCode)

	bodyBytes, _ := io.ReadAll(listResp.Body)
	var listData consentModel.ListResponse
	require.NoError(t, json.Unmarshal(bodyBytes, &listData))
	require.Len(t, listData.Consents, 3)

	for _, record := range listData.Consents {
		assert.Equal(t, consentModel.StatusActive, record.Status)
		assert.Nil(t, record.RevokedAt)
	}

	t.Log("Step 3: Revoke one consent (registry_check)")
	revokeBody, _ := json.Marshal(map[string]any{"purposes": []string{"registry_check"}})
	revokeResp, err := http.Post(server.URL+"/auth/consent/revoke", "application/json", bytes.NewReader(revokeBody))
	require.NoError(t, err)
	defer revokeResp.Body.Close()
	assert.Equal(t, http.StatusOK, revokeResp.StatusCode)

	revokeRespBody, _ := io.ReadAll(revokeResp.Body)
	var revokeData consentModel.RevokeResponse
	require.NoError(t, json.Unmarshal(revokeRespBody, &revokeData))
	assert.Len(t, revokeData.Revoked, 1)
	assert.Contains(t, revokeData.Message, "Consent revoked for 1 purpose")

	t.Log("Step 4: Expire a different consent (profile_access) by manipulating expiry time")
	expiredAt := time.Now().Add(-time.Hour)
	profileRecord, err := consentStore.FindByUserAndPurpose(context.Background(), "user123", consentModel.PurposeProfileAccess)
	require.NoError(t, err)
	require.NotNil(t, profileRecord)
	profileRecord.ExpiresAt = &expiredAt
	require.NoError(t, consentStore.Update(context.Background(), profileRecord))

	t.Log("Step 5: List consents and verify different statuses (active, revoked, expired)")
	listResp2, err := http.Get(server.URL + "/auth/consent")
	require.NoError(t, err)
	defer listResp2.Body.Close()
	assert.Equal(t, http.StatusOK, listResp2.StatusCode)

	bodyBytes2, _ := io.ReadAll(listResp2.Body)
	var listData2 consentModel.ListResponse
	require.NoError(t, json.Unmarshal(bodyBytes2, &listData2))
	require.Len(t, listData2.Consents, 3)

	statusCounts := map[string]int{}
	for _, record := range listData2.Consents {
		statusCounts[record.Status]++
		switch record.Purpose {
		case consentModel.PurposeLogin:
			assert.Equal(t, consentModel.StatusActive, record.Status, "login should be active")
			assert.Nil(t, record.RevokedAt)
			assert.NotNil(t, record.ExpiresAt)
			assert.True(t, record.ExpiresAt.After(time.Now()), "login expiry should be in future")
		case consentModel.PurposeRegistryCheck:
			assert.Equal(t, consentModel.StatusRevoked, record.Status, "registry_check should be revoked")
			assert.NotNil(t, record.RevokedAt)
		case consentModel.PurposeProfileAccess:
			assert.Equal(t, consentModel.StatusExpired, record.Status, "profile_access should be expired")
			assert.Nil(t, record.RevokedAt)
			assert.NotNil(t, record.ExpiresAt)
			assert.True(t, record.ExpiresAt.Before(time.Now()), "profile_access should be expired")
		}
	}
	assert.Equal(t, 1, statusCounts[consentModel.StatusActive], "should have 1 active consent")
	assert.Equal(t, 1, statusCounts[consentModel.StatusRevoked], "should have 1 revoked consent")
	assert.Equal(t, 1, statusCounts[consentModel.StatusExpired], "should have 1 expired consent")

	t.Log("Step 6: Re-grant the expired consent (profile_access)")
	regrantBody, _ := json.Marshal(map[string]any{"purposes": []string{"profile_access"}})
	regrantResp, err := http.Post(server.URL+"/auth/consent", "application/json", bytes.NewReader(regrantBody))
	require.NoError(t, err)
	defer regrantResp.Body.Close()
	assert.Equal(t, http.StatusOK, regrantResp.StatusCode)

	regrantRespBody, _ := io.ReadAll(regrantResp.Body)
	var regrantData consentModel.GrantResponse
	require.NoError(t, json.Unmarshal(regrantRespBody, &regrantData))
	assert.Len(t, regrantData.Granted, 1)
	assert.Equal(t, consentModel.PurposeProfileAccess, regrantData.Granted[0].Purpose)
	assert.Equal(t, consentModel.StatusActive, regrantData.Granted[0].Status)

	t.Log("Step 7: Final list - verify profile_access is now active again")
	listResp3, err := http.Get(server.URL + "/auth/consent")
	require.NoError(t, err)
	defer listResp3.Body.Close()
	assert.Equal(t, http.StatusOK, listResp3.StatusCode)

	bodyBytes3, _ := io.ReadAll(listResp3.Body)
	var listData3 consentModel.ListResponse
	require.NoError(t, json.Unmarshal(bodyBytes3, &listData3))
	require.Len(t, listData3.Consents, 3)

	finalStatusCounts := map[string]int{}
	for _, record := range listData3.Consents {
		finalStatusCounts[record.Status]++
		if record.Purpose == consentModel.PurposeProfileAccess {
			assert.Equal(t, consentModel.StatusActive, record.Status, "profile_access should be active after re-grant")
			assert.Nil(t, record.RevokedAt)
			assert.NotNil(t, record.ExpiresAt)
			assert.True(t, record.ExpiresAt.After(time.Now()), "re-granted consent should have future expiry")
		}
	}
	assert.Equal(t, 2, finalStatusCounts[consentModel.StatusActive], "should have 2 active consents (login + profile_access)")
	assert.Equal(t, 1, finalStatusCounts[consentModel.StatusRevoked], "should still have 1 revoked consent (registry_check)")
	assert.Equal(t, 0, finalStatusCounts[consentModel.StatusExpired], "should have 0 expired consents")

	t.Log("Step 8: Verify audit trail")
	auditEvents, err := auditStore.ListByUser(context.Background(), "user123")
	require.NoError(t, err)
	// Expected: 3 initial grants + 1 revoke + 1 re-grant = 5 events
	assert.Len(t, auditEvents, 5, "expected 5 audit events")

	actionCounts := map[string]int{}
	for _, event := range auditEvents {
		actionCounts[event.Action]++
		assert.Equal(t, "user123", event.UserID)
	}
	assert.Equal(t, 4, actionCounts["consent_granted"], "should have 4 grant events")
	assert.Equal(t, 1, actionCounts["consent_revoked"], "should have 1 revoke event")
}
