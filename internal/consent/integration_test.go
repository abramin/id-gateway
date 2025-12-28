// Package handler contains integration tests for consent module.
//
// These tests exercise the full stack (handler -> service -> store) with real
// components. They complement the e2e/features/consent_flow.feature scenarios
// by testing behaviors that cannot be expressed in Gherkin:
//
//  1. TestConsentExpiryAndIDReuse: Tests manual expiry manipulation and verifies
//     consent ID reuse (not expressible in Gherkin without time control). Focus:
//     expired status display, re-granting expired consent, ID reuse verification,
//     and audit trail counts.
//
//  2. TestIdempotencyWindowBoundary: Tests the 5-minute idempotency window
//     boundary including manual timestamp manipulation and verification of
//     audit event counts (timing-sensitive, not Gherkin-friendly).
//
//  3. TestConcurrentGrantRevoke: Tests race conditions which cannot be reliably
//     expressed or reproduced in feature scenarios.
//
// Why these are not Gherkin scenarios (per testing.md Secondary Layer):
// - Require direct store manipulation (expiry times, grant timestamps)
// - Verify internal audit event counts (not externally observable)
// - Test timing-sensitive idempotency window behavior
// - Need sub-second timing control not available in e2e tests
// - Test concurrency which cannot be expressed in Gherkin
//
// Per Credo testing doctrine (testing.md, AGENTS.md): these are SECONDARY tests
// that exist because the behavior cannot be expressed in Gherkin feature files.
// Basic grant/list/revoke flows are covered by e2e/features/consent_flow.feature.
package consent_test

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
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"credo/internal/consent/handler"
	consentdto "credo/internal/consent/handler/dto"
	consentModel "credo/internal/consent/models"
	"credo/internal/consent/service"
	"credo/internal/consent/store"
	id "credo/pkg/domain"
	auditpublisher "credo/pkg/platform/audit/publisher"
	auditstore "credo/pkg/platform/audit/store/memory"
	authmw "credo/pkg/platform/middleware/auth"
)

// consentTestHarness provides common setup for consent integration tests.
// Extracts the repeated router/middleware/server setup into a reusable struct.
type consentTestHarness struct {
	server       *httptest.Server
	consentStore *store.InMemoryStore
	auditStore   *auditstore.InMemoryStore
	userID       id.UserID
}

func newConsentTestHarness(userIDStr string) *consentTestHarness {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	consentStore := store.New()
	auditStore := auditstore.NewInMemoryStore()
	svc := service.New(
		consentStore,
		auditpublisher.NewPublisher(auditStore),
		logger,
		service.WithConsentTTL(365*24*time.Hour),
	)
	h := handler.New(svc, logger, nil)

	// Parse typed IDs for context injection (simulating auth middleware)
	parsedUserID, _ := id.ParseUserID(userIDStr)
	parsedSessionID, _ := id.ParseSessionID("550e8400-e29b-41d4-a716-446655440010")
	parsedClientID, _ := id.ParseClientID("550e8400-e29b-41d4-a716-446655440020")

	router := chi.NewRouter()
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), authmw.ContextKeyUserID, parsedUserID)
			ctx = context.WithValue(ctx, authmw.ContextKeySessionID, parsedSessionID)
			ctx = context.WithValue(ctx, authmw.ContextKeyClientID, parsedClientID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	router.Post("/auth/consent", h.HandleGrantConsent)
	router.Post("/auth/consent/revoke", h.HandleRevokeConsent)
	router.Post("/auth/consent/revoke-all", h.HandleRevokeAllConsents)
	router.Get("/auth/consent", h.HandleGetConsents)
	router.Delete("/auth/consent", h.HandleDeleteAllConsents)
	router.Post("/admin/consent/users/{user_id}/revoke-all", h.HandleAdminRevokeAllConsents)

	userID, _ := id.ParseUserID(userIDStr)
	return &consentTestHarness{
		server:       httptest.NewServer(router),
		consentStore: consentStore,
		auditStore:   auditStore,
		userID:       userID,
	}
}

func (h *consentTestHarness) Close() {
	h.server.Close()
}

func (h *consentTestHarness) grantConsent(t *testing.T, purposes []string) *consentdto.GrantResponse {
	body, _ := json.Marshal(map[string]any{"purposes": purposes})
	resp, err := http.Post(h.server.URL+"/auth/consent", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	respBody, _ := io.ReadAll(resp.Body)
	var data consentdto.GrantResponse
	require.NoError(t, json.Unmarshal(respBody, &data))
	return &data
}

func (h *consentTestHarness) listConsents(t *testing.T) *consentdto.ListResponse {
	resp, err := http.Get(h.server.URL + "/auth/consent")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var data consentdto.ListResponse
	require.NoError(t, json.Unmarshal(body, &data))
	return &data
}

func (h *consentTestHarness) revokeConsent(t *testing.T, purposes []string) *consentdto.RevokeResponse {
	body, _ := json.Marshal(map[string]any{"purposes": purposes})
	resp, err := http.Post(h.server.URL+"/auth/consent/revoke", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	respBody, _ := io.ReadAll(resp.Body)
	var data consentdto.RevokeResponse
	require.NoError(t, json.Unmarshal(respBody, &data))
	return &data
}

func (h *consentTestHarness) adminRevokeAllConsents(t *testing.T, userID id.UserID) *consentdto.RevokeResponse {
	resp, err := http.Post(h.server.URL+"/admin/consent/users/"+userID.String()+"/revoke-all", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	respBody, _ := io.ReadAll(resp.Body)
	var data consentdto.RevokeResponse
	require.NoError(t, json.Unmarshal(respBody, &data))
	return &data
}

// TestConsentExpiryAndIDReuse tests behaviors not expressible in Gherkin:
// - Manual expiry manipulation to create expired status
// - Expired consent display in list
// - Re-granting expired consent (distinct from re-granting revoked)
// - Consent ID reuse verification (internal state)
// - Audit trail count verification (internal state)
//
// Note: Basic grant/list/revoke are covered by consent_flow.feature.
func TestConsentExpiryAndIDReuse(t *testing.T) {
	h := newConsentTestHarness("550e8400-e29b-41d4-a716-446655440001")
	defer h.Close()

	// Setup: Create consents via HTTP (minimal setup, not testing grant itself)
	t.Log("Setup: Create initial consents")
	h.grantConsent(t, []string{"login", "registry_check", "vc_issuance"})
	h.revokeConsent(t, []string{"registry_check"})

	// Get the vc_issuance consent ID before expiring it
	vcRecord, err := h.consentStore.FindByUserAndPurpose(context.Background(), h.userID, consentModel.PurposeVCIssuance)
	require.NoError(t, err)
	require.NotNil(t, vcRecord)
	originalVCID := vcRecord.ID

	t.Log("Step 1: Expire vc_issuance by manipulating expiry time")
	expiredAt := time.Now().Add(-time.Hour)
	vcRecord.ExpiresAt = &expiredAt
	require.NoError(t, h.consentStore.Update(context.Background(), vcRecord))

	t.Log("Step 2: List consents and verify expired status is displayed correctly")
	listData := h.listConsents(t)
	require.Len(t, listData.Consents, 3)

	statusCounts := map[string]int{}
	for _, record := range listData.Consents {
		statusCounts[string(record.Status)]++
		switch record.Purpose {
		case consentModel.PurposeLogin.String():
			assert.Equal(t, string(consentModel.StatusActive), record.Status, "login should be active")
		case consentModel.PurposeRegistryCheck.String():
			assert.Equal(t, string(consentModel.StatusRevoked), record.Status, "registry_check should be revoked")
		case consentModel.PurposeVCIssuance.String():
			assert.Equal(t, string(consentModel.StatusExpired), record.Status, "vc_issuance should be expired")
			assert.True(t, record.ExpiresAt.Before(time.Now()), "vc_issuance expiry should be in past")
		}
	}
	assert.Equal(t, 1, statusCounts[string(consentModel.StatusActive)])
	assert.Equal(t, 1, statusCounts[string(consentModel.StatusRevoked)])
	assert.Equal(t, 1, statusCounts[string(consentModel.StatusExpired)])

	t.Log("Step 3: Re-grant the expired consent (distinct from re-granting revoked)")
	regrantData := h.grantConsent(t, []string{"vc_issuance"})
	require.Len(t, regrantData.Granted, 1)
	assert.Equal(t, consentModel.PurposeVCIssuance.String(), regrantData.Granted[0].Purpose)
	assert.Equal(t, string(consentModel.StatusActive), regrantData.Granted[0].Status)

	t.Log("Step 4: Verify consent ID was reused (not creating a new record)")
	regrantedRecord, err := h.consentStore.FindByUserAndPurpose(context.Background(), h.userID, consentModel.PurposeVCIssuance)
	require.NoError(t, err)
	assert.Equal(t, originalVCID, regrantedRecord.ID, "consent ID should be reused when re-granting expired consent")

	t.Log("Step 5: Verify final state - vc_issuance now active")
	finalList := h.listConsents(t)
	finalStatusCounts := map[string]int{}
	for _, record := range finalList.Consents {
		finalStatusCounts[string(record.Status)]++
	}
	assert.Equal(t, 2, finalStatusCounts[string(consentModel.StatusActive)], "should have 2 active (login + vc_issuance)")
	assert.Equal(t, 1, finalStatusCounts[string(consentModel.StatusRevoked)], "should have 1 revoked (registry_check)")

	t.Log("Step 6: Verify audit trail counts and payload content")
	auditEvents, err := h.auditStore.ListByUser(context.Background(), h.userID)
	require.NoError(t, err)
	// Expected: 3 initial grants + 1 revoke + 1 re-grant = 5 events
	assert.Len(t, auditEvents, 5, "expected 5 audit events")

	actionCounts := map[string]int{}
	for _, event := range auditEvents {
		actionCounts[event.Action]++

		// Verify payload structure for all events
		assert.Equal(t, h.userID, event.UserID, "event should have correct user ID")
		assert.False(t, event.Timestamp.IsZero(), "event should have timestamp")

		// Verify action-specific payload content
		switch event.Action {
		case consentModel.AuditActionConsentGranted:
			assert.NotEmpty(t, event.Purpose, "grant event should have purpose")
			assert.Equal(t, consentModel.AuditDecisionGranted, event.Decision, "grant event should have 'granted' decision")
			assert.Equal(t, consentModel.AuditReasonUserInitiated, event.Reason, "grant event should have reason")
		case consentModel.AuditActionConsentRevoked:
			assert.NotEmpty(t, event.Purpose, "revoke event should have purpose")
			assert.Equal(t, consentModel.AuditDecisionRevoked, event.Decision, "revoke event should have 'revoked' decision")
			assert.Equal(t, consentModel.AuditReasonUserInitiated, event.Reason, "revoke event should have reason")
		}
	}
	assert.Equal(t, 4, actionCounts["consent_granted"], "should have 4 grant events")
	assert.Equal(t, 1, actionCounts["consent_revoked"], "should have 1 revoke event")
}

func TestAdminRevokeAllConsents(t *testing.T) {
	h := newConsentTestHarness("550e8400-e29b-41d4-a716-446655440002")
	defer h.Close()

	h.grantConsent(t, []string{"login", "registry_check"})

	resp := h.adminRevokeAllConsents(t, h.userID)
	assert.Equal(t, "Consent revoked for 2 purposes", resp.Message)

	listData := h.listConsents(t)
	require.Len(t, listData.Consents, 2)
	for _, record := range listData.Consents {
		assert.Equal(t, string(consentModel.StatusRevoked), record.Status)
	}
}

// TestIdempotencyWindowBoundary tests the 5-minute idempotency window behavior.
// This cannot be expressed in Gherkin because:
// - Requires manual timestamp manipulation to simulate time passing
// - Verifies internal audit event counts (not externally observable)
// - Tests boundary conditions of the idempotency window
//
// Note: consent_flow.feature:100 tests renewal (waits 2s), but that's still
// within the 5-min window. This test verifies the boundary behavior.
func TestIdempotencyWindowBoundary(t *testing.T) {
	h := newConsentTestHarness("550e8400-e29b-41d4-a716-446655440003")
	defer h.Close()

	t.Log("Step 1: Initial consent grant")
	grant1 := h.grantConsent(t, []string{"login"})
	require.Len(t, grant1.Granted, 1)
	firstGrantedAt := grant1.Granted[0].GrantedAt
	firstExpiresAt := grant1.Granted[0].ExpiresAt

	// Get consent ID for verification
	record1, err := h.consentStore.FindByUserAndPurpose(context.Background(), h.userID, consentModel.PurposeLogin)
	require.NoError(t, err)
	consentID := record1.ID

	t.Log("Step 2: Immediate second grant (within 5-min window) - should be idempotent")
	time.Sleep(100 * time.Millisecond) // Small delay to ensure different timestamp if updated
	grant2 := h.grantConsent(t, []string{"login"})
	require.Len(t, grant2.Granted, 1)
	assert.Equal(t, firstGrantedAt, grant2.Granted[0].GrantedAt, "GrantedAt should NOT be updated within 5-min window")
	assert.Equal(t, firstExpiresAt, grant2.Granted[0].ExpiresAt, "ExpiresAt should NOT be updated within 5-min window")

	t.Log("Step 3: Verify audit trail - only 1 event (second was idempotent)")
	auditEvents, err := h.auditStore.ListByUser(context.Background(), h.userID)
	require.NoError(t, err)
	assert.Len(t, auditEvents, 1, "should only have 1 audit event (idempotent request didn't create new event)")

	t.Log("Step 4: Manipulate timestamp to simulate time passing (6 minutes ago)")
	record, err := h.consentStore.FindByUserAndPurpose(context.Background(), h.userID, consentModel.PurposeLogin)
	require.NoError(t, err)
	record.GrantedAt = time.Now().Add(-6 * time.Minute)
	require.NoError(t, h.consentStore.Update(context.Background(), record))

	t.Log("Step 5: Grant again (now outside 5-min window) - should update timestamps")
	grant3 := h.grantConsent(t, []string{"login"})
	require.Len(t, grant3.Granted, 1)
	assert.True(t, grant3.Granted[0].GrantedAt.After(firstGrantedAt), "GrantedAt should be updated after 5-min window")
	assert.True(t, grant3.Granted[0].ExpiresAt.After(*firstExpiresAt), "ExpiresAt should be updated after 5-min window")

	t.Log("Step 6: Verify consent ID is still reused")
	record3, err := h.consentStore.FindByUserAndPurpose(context.Background(), h.userID, consentModel.PurposeLogin)
	require.NoError(t, err)
	assert.Equal(t, consentID, record3.ID, "consent ID should still be reused")

	t.Log("Step 7: Verify audit trail - now has 2 events")
	auditEvents2, err := h.auditStore.ListByUser(context.Background(), h.userID)
	require.NoError(t, err)
	assert.Len(t, auditEvents2, 2, "should have 2 audit events (second grant was outside window)")
}

// TestConcurrentGrantRevoke verifies concurrent grant/revoke operations don't corrupt state.
// This is an integration test (not Gherkin) because it tests race conditions which
// cannot be reliably expressed or reproduced in feature scenarios.
func TestConcurrentGrantRevoke(t *testing.T) {
	h := newConsentTestHarness("550e8400-e29b-41d4-a716-446655440003")
	defer h.Close()

	// First, create an initial consent to operate on
	h.grantConsent(t, []string{"login"})

	t.Log("Running concurrent grant and revoke operations")

	const numGoroutines = 10
	errChan := make(chan error, numGoroutines*2)
	done := make(chan struct{})

	// Start concurrent grant operations
	for range numGoroutines {
		go func() {
			body, _ := json.Marshal(map[string]any{"purposes": []string{"login"}})
			resp, err := http.Post(h.server.URL+"/auth/consent", "application/json", bytes.NewReader(body))
			if err != nil {
				errChan <- err
				return
			}
			defer resp.Body.Close()
			errChan <- nil
		}()
	}

	// Start concurrent revoke operations
	for range numGoroutines {
		go func() {
			body, _ := json.Marshal(map[string]any{"purposes": []string{"login"}})
			resp, err := http.Post(h.server.URL+"/auth/consent/revoke", "application/json", bytes.NewReader(body))
			if err != nil {
				errChan <- err
				return
			}
			defer resp.Body.Close()
			errChan <- nil
		}()
	}

	// Wait for all goroutines
	go func() {
		for range numGoroutines * 2 {
			<-errChan
		}
		close(done)
	}()

	select {
	case <-done:
		// All goroutines completed
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for concurrent operations")
	}

	// Verify final state is consistent (exactly one record exists, in some valid state)
	record, err := h.consentStore.FindByUserAndPurpose(context.Background(), h.userID, consentModel.PurposeLogin)
	require.NoError(t, err)
	require.NotNil(t, record)

	// Record should be in a valid state (not corrupted)
	assert.NotEqual(t, id.ConsentID(uuid.Nil), record.ID, "record ID should be valid")
	assert.Equal(t, h.userID, record.UserID, "record userID should match")

	t.Log("Concurrent operations completed without panics or corrupted state")
}
