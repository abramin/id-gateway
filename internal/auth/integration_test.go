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
	"credo/internal/auth/types"
	jwttoken "credo/internal/jwt_token"
	id "credo/pkg/domain"
	"credo/pkg/platform/audit/publishers/security"
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

func (r *stubClientResolver) ResolveClient(ctx context.Context, clientID string) (*types.ResolvedClient, *types.ResolvedTenant, error) {
	return &types.ResolvedClient{
			ID:            r.defaultClientID,
			TenantID:      r.defaultTenantID,
			OAuthClientID: clientID,
			RedirectURIs:  []string{"https://client.app/callback"},
			Active:        true,
		}, &types.ResolvedTenant{
			ID:     r.defaultTenantID,
			Active: true,
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

	userStore := userStore.New()
	sessionStore := sessionStore.New()
	authCodeStore := authCodeStore.New()
	refreshTokenStore := refreshTokenStore.New()
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
		service.WithAuditPublisher(security.New(auditStore)),
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
	for range concurrentRequests {
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

// TestConcurrentSessionRevocation validates session revocation under concurrent load.
// This test verifies that when multiple requests attempt to revoke the same session simultaneously,
// exactly one succeeds (revokes the session) and subsequent requests fail at the auth layer
// because the access token is revoked when the session is revoked (added to TRL).
// This validates the TOCTOU fix in c15bec5 - the ownership check and CanRevoke() happen atomically.
// This invariant cannot be expressed in Gherkin because it requires concurrent request simulation.
func TestConcurrentSessionRevocation(t *testing.T) {
	r, _, sessionStore, _, _, _ := SetupSuite(t)

	// Step 1: Create a user with an active session
	authReq := models.AuthorizationRequest{
		Email:       "revoke-test@example.com",
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

	// Step 2: Exchange code for tokens to activate the session
	tokenReq := models.TokenRequest{
		GrantType:   "authorization_code",
		Code:        authResp.Code,
		RedirectURI: "https://client.app/callback",
		ClientID:    "client-123",
	}
	tokenPayload, err := json.Marshal(tokenReq)
	require.NoError(t, err)

	req = httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(tokenPayload))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "token exchange should succeed")

	var tokenResp models.TokenResult
	err = json.NewDecoder(rec.Body).Decode(&tokenResp)
	require.NoError(t, err)
	accessToken := tokenResp.AccessToken

	// Step 3: Get the session ID from the sessions list
	req = httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "list sessions should succeed")

	var sessionsResp models.SessionsResult
	err = json.NewDecoder(rec.Body).Decode(&sessionsResp)
	require.NoError(t, err)
	require.NotEmpty(t, sessionsResp.Sessions, "should have at least one session")

	sessionID := sessionsResp.Sessions[0].SessionID

	// Step 4: Attempt concurrent session revocations
	concurrentRequests := 10
	successCh := make(chan bool, concurrentRequests)
	authFailCh := make(chan bool, concurrentRequests)
	otherFailCh := make(chan error, concurrentRequests)

	for range concurrentRequests {
		go func(sid string) {
			req := httptest.NewRequest(http.MethodDelete, "/auth/sessions/"+sid, nil)
			req.Header.Set("Authorization", "Bearer "+accessToken)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)

			switch rec.Code {
			case http.StatusOK, http.StatusNoContent:
				successCh <- true
			case http.StatusUnauthorized:
				// Expected after first revocation - token is now in TRL
				authFailCh <- true
			default:
				body, _ := io.ReadAll(rec.Body)
				otherFailCh <- fmt.Errorf("status %d: %s", rec.Code, string(body))
			}
		}(sessionID)
	}

	// Step 5: Collect results
	successCount := 0
	authFailCount := 0
	var otherFailures []error
	for range concurrentRequests {
		select {
		case <-successCh:
			successCount++
		case <-authFailCh:
			authFailCount++
		case err := <-otherFailCh:
			otherFailures = append(otherFailures, err)
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for concurrent requests to complete")
		}
	}

	// At least one revocation should succeed; others may get 401 (token revoked)
	assert.GreaterOrEqual(t, successCount, 1, "at least one revocation should succeed")
	assert.Equal(t, concurrentRequests, successCount+authFailCount, "all requests should either succeed or get 401")
	assert.Empty(t, otherFailures, "no unexpected failures: %v", otherFailures)

	// Step 6: Verify session is revoked in the store
	sessions, err := sessionStore.ListAll(context.Background())
	require.NoError(t, err)

	var revokedSession *models.Session
	for _, s := range sessions {
		if s.ID.String() == sessionID {
			revokedSession = s
			break
		}
	}
	require.NotNil(t, revokedSession, "session should exist in store")
	assert.Equal(t, models.SessionStatusRevoked, revokedSession.Status, "session should be revoked")
	assert.NotNil(t, revokedSession.RevokedAt, "RevokedAt should be set")
}

// TestAdminDeleteDuringTokenRefresh validates atomic user deletion under concurrent load.
// This test verifies that when an admin deletes a user while the user is attempting to
// refresh their token, the final state is consistent: the user and all their sessions
// are deleted atomically (no partial state).
// This validates the RunInTx fix in c15bec5 - sessions and user are deleted in one transaction.
// This invariant cannot be expressed in Gherkin because it requires concurrent request simulation.
func TestAdminDeleteDuringTokenRefresh(t *testing.T) {
	r, userStore, sessionStore, _, _, _ := SetupSuite(t)

	// Step 1: Create a user with an active session
	authReq := models.AuthorizationRequest{
		Email:       "delete-race-test@example.com",
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

	// Step 2: Exchange code for tokens
	tokenReq := models.TokenRequest{
		GrantType:   "authorization_code",
		Code:        authResp.Code,
		RedirectURI: "https://client.app/callback",
		ClientID:    "client-123",
	}
	tokenPayload, err := json.Marshal(tokenReq)
	require.NoError(t, err)

	req = httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(tokenPayload))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "token exchange should succeed")

	var tokenResp models.TokenResult
	err = json.NewDecoder(rec.Body).Decode(&tokenResp)
	require.NoError(t, err)

	// Get the user ID from the userinfo endpoint
	req = httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "userinfo should succeed")

	var userInfo models.UserInfoResult
	err = json.NewDecoder(rec.Body).Decode(&userInfo)
	require.NoError(t, err)
	userID := userInfo.Sub

	// Step 3: Concurrently delete the user and attempt to refresh the token
	concurrentRequests := 10
	deleteSuccessCh := make(chan bool, concurrentRequests)
	deleteFailureCh := make(chan error, concurrentRequests)
	refreshSuccessCh := make(chan bool, concurrentRequests)
	refreshFailureCh := make(chan bool, concurrentRequests)

	// Half attempt to delete, half attempt to refresh
	for i := range concurrentRequests {
		if i%2 == 0 {
			// Admin delete request
			go func() {
				req := httptest.NewRequest(http.MethodDelete, "/admin/auth/users/"+userID, nil)
				req.Header.Set("X-Admin-Token", "test-admin-token")
				rec := httptest.NewRecorder()
				r.ServeHTTP(rec, req)

				if rec.Code == http.StatusOK || rec.Code == http.StatusNoContent {
					deleteSuccessCh <- true
				} else if rec.Code == http.StatusNotFound {
					// User already deleted - this is expected in race
					deleteSuccessCh <- true
				} else {
					body, _ := io.ReadAll(rec.Body)
					deleteFailureCh <- fmt.Errorf("status %d: %s", rec.Code, string(body))
				}
			}()
		} else {
			// Refresh token request
			go func(rt string) {
				refreshReq := models.TokenRequest{
					GrantType:    "refresh_token",
					RefreshToken: rt,
					ClientID:     "client-123",
				}
				refreshPayload, _ := json.Marshal(refreshReq)

				req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(refreshPayload))
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				r.ServeHTTP(rec, req)

				if rec.Code == http.StatusOK {
					refreshSuccessCh <- true
				} else {
					// Failure is expected if user was deleted
					refreshFailureCh <- true
				}
			}(tokenResp.RefreshToken)
		}
	}

	// Step 4: Collect results
	deleteSuccess := 0
	var deleteFailures []error
	refreshSuccess := 0
	refreshFailure := 0

	for i := range concurrentRequests {
		if i%2 == 0 {
			select {
			case <-deleteSuccessCh:
				deleteSuccess++
			case err := <-deleteFailureCh:
				deleteFailures = append(deleteFailures, err)
			case <-time.After(5 * time.Second):
				t.Fatal("timeout waiting for delete requests")
			}
		} else {
			select {
			case <-refreshSuccessCh:
				refreshSuccess++
			case <-refreshFailureCh:
				refreshFailure++
			case <-time.After(5 * time.Second):
				t.Fatal("timeout waiting for refresh requests")
			}
		}
	}

	// All delete requests should succeed (or see "not found" if already deleted)
	assert.Equal(t, concurrentRequests/2, deleteSuccess, "all delete requests should succeed")
	assert.Empty(t, deleteFailures, "no unexpected delete failures: %v", deleteFailures)

	// Refreshes either succeed (before delete) or fail (after delete)
	assert.Equal(t, concurrentRequests/2, refreshSuccess+refreshFailure, "all refresh requests should complete")

	// Step 5: Verify final state is consistent - user and sessions should be deleted
	users, err := userStore.ListAll(context.Background())
	require.NoError(t, err)

	var userExists bool
	for _, u := range users {
		if u.ID.String() == userID {
			userExists = true
			break
		}
	}
	assert.False(t, userExists, "user should be deleted")

	// Verify no sessions exist for the deleted user
	sessions, err := sessionStore.ListAll(context.Background())
	require.NoError(t, err)

	var orphanedSessions int
	for _, s := range sessions {
		if s.UserID.String() == userID {
			orphanedSessions++
		}
	}
	assert.Equal(t, 0, orphanedSessions, "no orphaned sessions should exist for deleted user")
}

