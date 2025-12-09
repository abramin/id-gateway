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
	consentModel "id-gateway/internal/consent/models"
	"id-gateway/internal/consent/service"
	"id-gateway/internal/consent/store"
	"id-gateway/internal/platform/middleware"
)

/*Issues Found:

Grant endpoint response structure - The test expects the grant response but doesn't validate it. According to PRD FR-1, it should return ConsentActionResponse with granted array and message.

Revoke response not validated - Test doesn't check the revoke response structure at all.

Purpose comparison issue - The test compares purpose string directly ("registry_check"), but ConsentPurpose is a custom type.

Missing grant response validation - Should verify the granted response contains the expected fields.

Status field access - The test assumes Status is a string field on ConsentRecord, but based on the code it's now part of ConsentRecordWithStatus.*/

func TestConsentIntegrationFlow(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	consentStore := store.NewInMemoryStore()
	auditStore := audit.NewInMemoryStore()
	svc := service.NewService(consentStore, service.WithNow(func() time.Time {
		return time.Date(2025, 12, 3, 10, 0, 0, 0, time.UTC)
	}), service.WithAuditor(audit.NewPublisher(auditStore)))
	handler := New(svc, logger, nil)

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

	// 1. Grant consent for multiple purposes
	grantBody, _ := json.Marshal(map[string]any{"purposes": []string{"login", "registry_check"}})
	resp, err := http.Post(server.URL+"/auth/consent", "application/json", bytes.NewReader(grantBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify grant response
	grantRespBody, _ := io.ReadAll(resp.Body)
	var grantData consentModel.ConsentActionResponse
	require.NoError(t, json.Unmarshal(grantRespBody, &grantData))
	assert.Len(t, grantData.Granted, 2)
	assert.Contains(t, grantData.Message, "Consent granted for 2 purposes")
	for _, g := range grantData.Granted {
		assert.Equal(t, "active", g.Status)
		assert.NotNil(t, g.ExpiresAt)
	}

	// 2. List consents and verify both are active
	listResp, err := http.Get(server.URL + "/auth/consent")
	require.NoError(t, err)
	defer listResp.Body.Close()
	assert.Equal(t, http.StatusOK, listResp.StatusCode)

	bodyBytes, _ := io.ReadAll(listResp.Body)
	var listData consentModel.ConsentRecordsResponse
	require.NoError(t, json.Unmarshal(bodyBytes, &listData))
	require.Len(t, listData.ConsentRecords, 2)

	// Verify all consents are active
	for _, record := range listData.ConsentRecords {
		assert.Equal(t, consentModel.ConsentStatusActive, record.Status)
		assert.Nil(t, record.RevokedAt)
	}

	// 3. Revoke one consent
	revokeBody, _ := json.Marshal(map[string]any{"purposes": []string{"registry_check"}})
	revokeResp, err := http.Post(server.URL+"/auth/consent/revoke", "application/json", bytes.NewReader(revokeBody))
	require.NoError(t, err)
	defer revokeResp.Body.Close()
	assert.Equal(t, http.StatusOK, revokeResp.StatusCode)

	// Verify revoke response
	revokeRespBody, _ := io.ReadAll(revokeResp.Body)
	var revokeData consentModel.ConsentActionResponse
	require.NoError(t, json.Unmarshal(revokeRespBody, &revokeData))
	assert.Len(t, revokeData.Granted, 1) // Revoke response uses "Granted" field (see handler)
	assert.Contains(t, revokeData.Message, "Consent revoked for 1 purpose")

	// 4. List consents again and verify revoked status
	listResp2, err := http.Get(server.URL + "/auth/consent")
	require.NoError(t, err)
	defer listResp2.Body.Close()
	assert.Equal(t, http.StatusOK, listResp2.StatusCode)

	bodyBytes2, _ := io.ReadAll(listResp2.Body)
	var listData2 consentModel.ConsentRecordsResponse
	require.NoError(t, json.Unmarshal(bodyBytes2, &listData2))
	require.Len(t, listData2.ConsentRecords, 2)

	// Verify status changes: login should still be active, registry_check should be revoked
	loginFound := false
	registryCheckFound := false
	for _, record := range listData2.ConsentRecords {
		if record.Purpose == consentModel.ConsentPurposeLogin {
			loginFound = true
			assert.Equal(t, consentModel.ConsentStatusActive, record.Status)
			assert.Nil(t, record.RevokedAt)
		} else if record.Purpose == consentModel.ConsentPurposeRegistryCheck {
			registryCheckFound = true
			assert.Equal(t, consentModel.ConsentStatusRevoked, record.Status)
			assert.NotNil(t, record.RevokedAt)
		}
	}
	assert.True(t, loginFound, "login consent not found")
	assert.True(t, registryCheckFound, "registry_check consent not found")
}
