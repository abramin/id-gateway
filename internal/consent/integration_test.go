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
	svc := service.NewService(
		consentStore,
		audit.NewPublisher(auditStore),
		logger,
		service.WithConsentTTL(365*24*time.Hour),
	)
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
	grantBody, _ := json.Marshal(map[string]any{"purposes": []string{"login", "registry_check", "vc_issuance"}})
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

	t.Log("Step 4: Expire a different consent (vc_issuance) by manipulating expiry time")
	expiredAt := time.Now().Add(-time.Hour)
	vcRecord, err := consentStore.FindByUserAndPurpose(context.Background(), "user123", consentModel.PurposeVCIssuance)
	require.NoError(t, err)
	require.NotNil(t, vcRecord)
	originalVCID := vcRecord.ID // Store original ID to verify reuse
	vcRecord.ExpiresAt = &expiredAt
	require.NoError(t, consentStore.Update(context.Background(), vcRecord))

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
		statusCounts[string(record.Status)]++
		switch record.Purpose {
		case consentModel.PurposeLogin:
			assert.Equal(t, consentModel.StatusActive, record.Status, "login should be active")
			assert.Nil(t, record.RevokedAt)
			assert.NotNil(t, record.ExpiresAt)
			assert.True(t, record.ExpiresAt.After(time.Now()), "login expiry should be in future")
		case consentModel.PurposeRegistryCheck:
			assert.Equal(t, consentModel.StatusRevoked, record.Status, "registry_check should be revoked")
			assert.NotNil(t, record.RevokedAt)
		case consentModel.PurposeVCIssuance:
			assert.Equal(t, consentModel.StatusExpired, record.Status, "vc_issuance should be expired")
			assert.Nil(t, record.RevokedAt)
			assert.NotNil(t, record.ExpiresAt)
			assert.True(t, record.ExpiresAt.Before(time.Now()), "vc_issuance should be expired")
		}
	}
	assert.Equal(t, 1, statusCounts[string(consentModel.StatusActive)], "should have 1 active consent")
	assert.Equal(t, 1, statusCounts[string(consentModel.StatusRevoked)], "should have 1 revoked consent")
	assert.Equal(t, 1, statusCounts[string(consentModel.StatusExpired)], "should have 1 expired consent")

	t.Log("Step 6: Re-grant the expired consent (vc_issuance)")
	regrantBody, _ := json.Marshal(map[string]any{"purposes": []string{"vc_issuance"}})
	regrantResp, err := http.Post(server.URL+"/auth/consent", "application/json", bytes.NewReader(regrantBody))
	require.NoError(t, err)
	defer regrantResp.Body.Close()
	assert.Equal(t, http.StatusOK, regrantResp.StatusCode)

	regrantRespBody, _ := io.ReadAll(regrantResp.Body)
	var regrantData consentModel.GrantResponse
	require.NoError(t, json.Unmarshal(regrantRespBody, &regrantData))
	assert.Len(t, regrantData.Granted, 1)
	assert.Equal(t, consentModel.PurposeVCIssuance, regrantData.Granted[0].Purpose)
	assert.Equal(t, consentModel.StatusActive, regrantData.Granted[0].Status)

	// Verify the consent ID was reused (not creating a new record)
	regrantedRecord, err := consentStore.FindByUserAndPurpose(context.Background(), "user123", consentModel.PurposeVCIssuance)
	require.NoError(t, err)
	assert.Equal(t, originalVCID, regrantedRecord.ID, "consent ID should be reused when re-granting expired consent")

	t.Log("Step 7: Final list - verify vc_issuance is now active again")
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
		finalStatusCounts[string(record.Status)]++
		if record.Purpose == consentModel.PurposeVCIssuance {
			assert.Equal(t, consentModel.StatusActive, record.Status, "vc_issuance should be active after re-grant")
			assert.Nil(t, record.RevokedAt)
			assert.NotNil(t, record.ExpiresAt)
			assert.True(t, record.ExpiresAt.After(time.Now()), "re-granted consent should have future expiry")
		}
	}
	assert.Equal(t, 2, finalStatusCounts[string(consentModel.StatusActive)], "should have 2 active consents (login + vc_issuance)")
	assert.Equal(t, 1, finalStatusCounts[string(consentModel.StatusRevoked)], "should still have 1 revoked consent (registry_check)")
	assert.Equal(t, 0, finalStatusCounts[string(consentModel.StatusExpired)], "should have 0 expired consents")

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

func TestConsentIdempotencyWindow(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	consentStore := store.NewInMemoryStore()
	auditStore := audit.NewInMemoryStore()
	svc := service.NewService(consentStore, audit.NewPublisher(auditStore), logger, 365*24*time.Hour)
	handler := handler.New(svc, logger, nil)

	router := chi.NewRouter()
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), middleware.ContextKeyUserID, "user456")
			ctx = context.WithValue(ctx, middleware.ContextKeySessionID, "session456")
			ctx = context.WithValue(ctx, middleware.ContextKeyClientID, "client456")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	handler.Register(router)

	server := httptest.NewServer(router)
	defer server.Close()

	t.Log("Step 1: Initial consent grant")
	grantBody, _ := json.Marshal(map[string]any{"purposes": []string{"login"}})
	resp1, err := http.Post(server.URL+"/auth/consent", "application/json", bytes.NewReader(grantBody))
	require.NoError(t, err)
	defer resp1.Body.Close()
	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	body1, _ := io.ReadAll(resp1.Body)
	var grant1 consentModel.GrantResponse
	require.NoError(t, json.Unmarshal(body1, &grant1))
	require.Len(t, grant1.Granted, 1)
	firstGrantedAt := grant1.Granted[0].GrantedAt
	firstExpiresAt := grant1.Granted[0].ExpiresAt

	// Get consent ID from store for verification
	record1, err := consentStore.FindByUserAndPurpose(context.Background(), "user456", consentModel.PurposeLogin)
	require.NoError(t, err)
	consentID := record1.ID

	t.Log("Step 2: Immediate second grant (within 5-min window) - should be idempotent")
	time.Sleep(100 * time.Millisecond) // Small delay to ensure different timestamp if updated
	resp2, err := http.Post(server.URL+"/auth/consent", "application/json", bytes.NewReader(grantBody))
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	body2, _ := io.ReadAll(resp2.Body)
	var grant2 consentModel.GrantResponse
	require.NoError(t, json.Unmarshal(body2, &grant2))
	require.Len(t, grant2.Granted, 1)

	// Verify consent ID is unchanged by checking store
	record2, err := consentStore.FindByUserAndPurpose(context.Background(), "user456", consentModel.PurposeLogin)
	require.NoError(t, err)
	assert.Equal(t, consentID, record2.ID, "consent ID should be unchanged")
	assert.Equal(t, firstGrantedAt, grant2.Granted[0].GrantedAt, "GrantedAt should not be updated within 5-min window")
	assert.Equal(t, firstExpiresAt, grant2.Granted[0].ExpiresAt, "ExpiresAt should not be updated within 5-min window")

	t.Log("Step 3: Verify audit trail - should only have 1 grant event (second was idempotent)")
	auditEvents, err := auditStore.ListByUser(context.Background(), "user456")
	require.NoError(t, err)
	assert.Len(t, auditEvents, 1, "should only have 1 audit event (idempotent request didn't create new event)")
	assert.Equal(t, "consent_granted", auditEvents[0].Action)

	t.Log("Step 4: Simulate time passing - manually update GrantedAt to 6 minutes ago")
	record, err := consentStore.FindByUserAndPurpose(context.Background(), "user456", consentModel.PurposeLogin)
	require.NoError(t, err)
	record.GrantedAt = time.Now().Add(-6 * time.Minute)
	require.NoError(t, consentStore.Update(context.Background(), record))

	t.Log("Step 5: Grant again (now outside 5-min window) - should update timestamps")
	resp3, err := http.Post(server.URL+"/auth/consent", "application/json", bytes.NewReader(grantBody))
	require.NoError(t, err)
	defer resp3.Body.Close()
	assert.Equal(t, http.StatusOK, resp3.StatusCode)

	body3, _ := io.ReadAll(resp3.Body)
	var grant3 consentModel.GrantResponse
	require.NoError(t, json.Unmarshal(body3, &grant3))
	require.Len(t, grant3.Granted, 1)

	// Verify consent ID is still reused by checking store
	record3, err := consentStore.FindByUserAndPurpose(context.Background(), "user456", consentModel.PurposeLogin)
	require.NoError(t, err)
	assert.Equal(t, consentID, record3.ID, "consent ID should still be reused")
	assert.True(t, grant3.Granted[0].GrantedAt.After(firstGrantedAt), "GrantedAt should be updated after 5-min window")
	assert.True(t, grant3.Granted[0].ExpiresAt.After(*firstExpiresAt), "ExpiresAt should be updated after 5-min window")

	t.Log("Step 6: Verify audit trail - should now have 2 grant events")
	auditEvents2, err := auditStore.ListByUser(context.Background(), "user456")
	require.NoError(t, err)
	assert.Len(t, auditEvents2, 2, "should have 2 audit events (second grant was outside window)")

	t.Log("Step 7: Revoke consent and immediately re-grant - should update despite time window")
	revokeBody, _ := json.Marshal(map[string]any{"purposes": []string{"login"}})
	revokeResp, err := http.Post(server.URL+"/auth/consent/revoke", "application/json", bytes.NewReader(revokeBody))
	require.NoError(t, err)
	defer revokeResp.Body.Close()
	assert.Equal(t, http.StatusOK, revokeResp.StatusCode)

	// Immediate re-grant of revoked consent
	resp4, err := http.Post(server.URL+"/auth/consent", "application/json", bytes.NewReader(grantBody))
	require.NoError(t, err)
	defer resp4.Body.Close()
	assert.Equal(t, http.StatusOK, resp4.StatusCode)

	body4, _ := io.ReadAll(resp4.Body)
	var grant4 consentModel.GrantResponse
	require.NoError(t, json.Unmarshal(body4, &grant4))
	require.Len(t, grant4.Granted, 1)

	// Verify consent ID is still reused by checking store
	record4, err := consentStore.FindByUserAndPurpose(context.Background(), "user456", consentModel.PurposeLogin)
	require.NoError(t, err)
	assert.Equal(t, consentID, record4.ID, "consent ID should still be reused")
	assert.True(t, grant4.Granted[0].GrantedAt.After(grant3.Granted[0].GrantedAt), "GrantedAt should be updated for revoked consent")
	assert.Equal(t, consentModel.StatusActive, grant4.Granted[0].Status)

	t.Log("Step 8: Final audit check - should have 3 grants + 1 revoke")
	auditEvents3, err := auditStore.ListByUser(context.Background(), "user456")
	require.NoError(t, err)
	assert.Len(t, auditEvents3, 4, "should have 4 audit events total")

	actionCounts := map[string]int{}
	for _, event := range auditEvents3 {
		actionCounts[event.Action]++
	}
	assert.Equal(t, 3, actionCounts["consent_granted"], "should have 3 grant events (excluding 1 idempotent)")
	assert.Equal(t, 1, actionCounts["consent_revoked"], "should have 1 revoke event")
}
