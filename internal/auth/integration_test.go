package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	auth "credo/internal/auth/handler"
	"credo/internal/auth/models"
	"credo/internal/auth/service"
	authCodeStore "credo/internal/auth/store/authorization-code"
	refreshTokenStore "credo/internal/auth/store/refresh-token"
	sessionStore "credo/internal/auth/store/session"
	userStore "credo/internal/auth/store/user"
	jwttoken "credo/internal/jwt_token"
	tenantModels "credo/internal/tenant/models"
	id "credo/pkg/domain"
	auditpublisher "credo/pkg/platform/audit/publisher"
	auditstore "credo/pkg/platform/audit/store/memory"
	adminmw "credo/pkg/platform/middleware/admin"
	authmw "credo/pkg/platform/middleware/auth"
	metadata "credo/pkg/platform/middleware/metadata"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubClientResolver provides a simple test implementation of ClientResolver
type stubClientResolver struct {
	defaultTenantID id.TenantID
	defaultClientID id.ClientID
}

func (r *stubClientResolver) ResolveClient(ctx context.Context, clientID string) (*tenantModels.Client, *tenantModels.Tenant, error) {
	return &tenantModels.Client{
			ID:            r.defaultClientID,
			TenantID:      r.defaultTenantID,
			OAuthClientID: clientID,
			Name:          "Test Client",
			Status:        "active",
			RedirectURIs:  []string{"https://client.app/callback"},
		}, &tenantModels.Tenant{
			ID:     r.defaultTenantID,
			Name:   "Test Tenant",
			Status: "active",
		}, nil
}

func SetupSuite(t *testing.T) (
	*chi.Mux,
	*userStore.InMemoryUserStore,
	*sessionStore.InMemorySessionStore,
	*authCodeStore.InMemoryAuthorizationCodeStore,
	*jwttoken.JWTService,
	*auditstore.InMemoryStore,
) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	userStore := userStore.NewInMemoryUserStore()
	sessionStore := sessionStore.NewInMemorySessionStore()
	authCodeStore := authCodeStore.NewInMemoryAuthorizationCodeStore()
	refreshTokenStore := refreshTokenStore.NewInMemoryRefreshTokenStore()
	jwtService := jwttoken.NewJWTService(
		"test-secret-key",
		"credo",
		"credo-client",
		15*time.Minute,
	)
	auditStore := auditstore.NewInMemoryStore()
	jwtValidator := jwttoken.NewJWTServiceAdapter(jwtService)
	clientResolver := &stubClientResolver{
		defaultTenantID: id.TenantID(uuid.New()),
		defaultClientID: id.ClientID(uuid.New()),
	}
	cfg := service.Config{
		SessionTTL:             24 * time.Hour,
		TokenTTL:               15 * time.Minute,
		AllowedRedirectSchemes: []string{"https", "http"},
		DeviceBindingEnabled:   true,
	}
	authService, _ := service.New(userStore, sessionStore, authCodeStore, refreshTokenStore,
		jwtService,
		clientResolver,
		&cfg,
		service.WithLogger(logger),
		service.WithAuditPublisher(auditpublisher.NewPublisher(auditStore)),
	)

	router := chi.NewRouter()
	router.Use(metadata.NewMiddleware(nil).Handler)
	authHandler := auth.New(authService, nil, nil, logger, "__Secure-Device-ID", 31536000)

	// Public endpoints (no auth required) - mirrors production setup
	router.Post("/auth/authorize", authHandler.HandleAuthorize)
	router.Post("/auth/token", authHandler.HandleToken)
	router.Post("/auth/revoke", authHandler.HandleRevoke)

	// Protected endpoints (auth required)
	router.Group(func(r chi.Router) {
		r.Use(authmw.RequireAuth(jwtValidator, authService, logger)) // authService implements TokenRevocationChecker
		r.Get("/auth/userinfo", authHandler.HandleUserInfo)
		r.Get("/auth/sessions", authHandler.HandleListSessions)
		r.Delete("/auth/sessions/{session_id}", authHandler.HandleRevokeSession)
	})

	// Admin endpoints (admin token required)
	router.Group(func(r chi.Router) {
		r.Use(adminmw.RequireAdminToken("test-admin-token", logger))
		authHandler.RegisterAdmin(r)
	})

	return router, userStore, sessionStore, authCodeStore, jwtService, auditStore
}

// TestConcurrentUserCreation validates race condition handling (PRD-001 Integration Test)
// NOTE: This test is retained because race conditions cannot be expressed in Gherkin/BDD format.
// Other integration tests (OAuth flow, token revocation, session management, admin delete)
// have been consolidated into Cucumber E2E tests in e2e/features/.
func TestConcurrentUserCreation(t *testing.T) {
	r, userStore, _, _, _, _ := SetupSuite(t)
	concurrentRequests := 10
	errCh := make(chan error, concurrentRequests)

	for range concurrentRequests {
		go func() {
			reqBody := models.AuthorizationRequest{
				Email:       "testuser@example.com",
				ClientID:    "client-123",
				Scopes:      []string{"openid"},
				RedirectURI: "https://client.app/callback",
			}
			payload, err := json.Marshal(reqBody)
			if err != nil {
				errCh <- err
				return
			}

			req := httptest.NewRequest(http.MethodPost, "/auth/authorize", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			r.ServeHTTP(rec, req)
			res := rec.Result()
			defer res.Body.Close()

			if res.StatusCode != http.StatusOK {
				errCh <- fmt.Errorf("expected status 200, got %d", res.StatusCode)
				return
			}

			errCh <- nil
		}()
	}

	for range concurrentRequests {
		err := <-errCh
		require.NoError(t, err)
	}

	users, err := userStore.ListAll(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, len(users), "expected only one user to be created")
}

// TestConcurrentAuthorizationCodeReplay validates replay protection under concurrent load.
// This test verifies that when the same authorization code is used concurrently by multiple
// requests, only ONE request succeeds and all others receive invalid_grant errors.
// This is a critical security invariant that cannot be expressed in Gherkin.
func TestConcurrentAuthorizationCodeReplay(t *testing.T) {
	r, _, _, _, _, _ := SetupSuite(t)

	// Step 1: Get an authorization code
	authReq := models.AuthorizationRequest{
		Email:       "replay-test@example.com",
		ClientID:    "client-123",
		Scopes:      []string{"openid"},
		RedirectURI: "https://client.app/callback",
	}
	payload, err := json.Marshal(authReq)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/authorize", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "authorization should succeed")

	var authResp models.AuthorizationResult
	err = json.NewDecoder(rec.Body).Decode(&authResp)
	require.NoError(t, err)
	require.NotEmpty(t, authResp.Code, "authorization code should be returned")

	// Step 2: Attempt concurrent token exchanges with the same code
	concurrentRequests := 10
	successCh := make(chan bool, concurrentRequests)
	failureCh := make(chan bool, concurrentRequests)

	for range concurrentRequests {
		go func(code string) {
			tokenReq := models.TokenRequest{
				GrantType:   "authorization_code",
				Code:        code,
				RedirectURI: "https://client.app/callback",
				ClientID:    "client-123",
			}
			tokenPayload, _ := json.Marshal(tokenReq)

			req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(tokenPayload))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)

			if rec.Code == http.StatusOK {
				successCh <- true
			} else {
				// Should be 400 Bad Request with invalid_grant
				failureCh <- true
			}
		}(authResp.Code)
	}

	// Step 3: Collect results and verify exactly one success
	successCount := 0
	failureCount := 0
	for i := 0; i < concurrentRequests; i++ {
		select {
		case <-successCh:
			successCount++
		case <-failureCh:
			failureCount++
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for concurrent requests to complete")
		}
	}

	assert.Equal(t, 1, successCount, "exactly one token exchange should succeed")
	assert.Equal(t, concurrentRequests-1, failureCount, "all other requests should fail with invalid_grant")
}
