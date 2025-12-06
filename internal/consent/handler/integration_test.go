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
	"id-gateway/internal/consent/service"
	"id-gateway/internal/consent/store"
	"id-gateway/internal/platform/middleware"
)

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

	// Grant consent
	grantBody, _ := json.Marshal(map[string]any{"purposes": []string{"login", "registry_check"}})
	resp, err := http.Post(server.URL+"/auth/consent", "application/json", bytes.NewReader(grantBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// List consents
	listResp, err := http.Get(server.URL + "/auth/consent")
	require.NoError(t, err)
	defer listResp.Body.Close()
	bodyBytes, _ := io.ReadAll(listResp.Body)
	var listData map[string]any
	require.NoError(t, json.Unmarshal(bodyBytes, &listData))
	consents := listData["consents"].([]any)
	require.Len(t, consents, 2)

	// Revoke one consent
	revokeBody, _ := json.Marshal(map[string]any{"purposes": []string{"registry_check"}})
	revokeResp, err := http.Post(server.URL+"/auth/consent/revoke", "application/json", bytes.NewReader(revokeBody))
	require.NoError(t, err)
	defer revokeResp.Body.Close()
	assert.Equal(t, http.StatusOK, revokeResp.StatusCode)

	// Verify revoked status appears
	listResp2, err := http.Get(server.URL + "/auth/consent")
	require.NoError(t, err)
	defer listResp2.Body.Close()
	bodyBytes2, _ := io.ReadAll(listResp2.Body)
	var listData2 map[string]any
	require.NoError(t, json.Unmarshal(bodyBytes2, &listData2))
	consents2 := listData2["consents"].([]any)

	revokedCount := 0
	for _, raw := range consents2 {
		consent := raw.(map[string]any)
		if consent["purpose"] == "registry_check" {
			assert.Equal(t, "revoked", consent["status"])
			revokedCount++
		}
	}
	assert.Equal(t, 1, revokedCount)
}
