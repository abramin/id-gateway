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

	"credo/internal/audit"
	auth "credo/internal/auth/handler"
	"credo/internal/auth/models"
	"credo/internal/auth/service"
	authCodeStore "credo/internal/auth/store/authorization-code"
	refreshTokenStore "credo/internal/auth/store/refresh-token"
	sessionStore "credo/internal/auth/store/session"
	userStore "credo/internal/auth/store/user"
	jwttoken "credo/internal/jwt_token"
	"credo/internal/platform/middleware"
	dErrors "credo/pkg/domain-errors"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func SetupSuite(t *testing.T) (
	*chi.Mux,
	*userStore.InMemoryUserStore,
	*sessionStore.InMemorySessionStore,
	*jwttoken.JWTService,
	*audit.InMemoryStore,
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
	auditStore := audit.NewInMemoryStore()
	jwtValidator := jwttoken.NewJWTServiceAdapter(jwtService)
	authService := service.NewService(userStore, sessionStore, authCodeStore, refreshTokenStore,
		service.WithSessionTTL(5*time.Minute),
		service.WithLogger(logger),
		service.WithJWTService(jwtService),
		service.WithAuditPublisher(audit.NewPublisher(auditStore)),
	)

	router := chi.NewRouter()
	authHandler := auth.New(authService, logger)

	// Public endpoints (no auth required) - mirrors production setup
	router.Post("/auth/authorize", authHandler.HandleAuthorize)
	router.Post("/auth/token", authHandler.HandleToken)

	// Protected endpoints (auth required)
	router.Group(func(r chi.Router) {
		r.Use(middleware.RequireAuth(jwtValidator, logger))
		r.Get("/auth/userinfo", authHandler.HandleUserInfo)
	})

	// Admin endpoints (admin token required)
	router.Group(func(r chi.Router) {
		r.Use(middleware.RequireAdminToken("test-admin-token", logger))
		authHandler.RegisterAdmin(r)
	})

	return router, userStore, sessionStore, jwtService, auditStore
}

func TestCompleteAuthFlow(t *testing.T) {
	r, userStore, sessionStore, _, auditStore := SetupSuite(t)
	reqBody := models.AuthorizationRequest{
		Email:       "jane.doe@example.com",
		ClientID:    "client-123",
		Scopes:      []string{"openid", "profile"},
		RedirectURI: "https://client.app/callback",
		State:       "state-xyz",
	}
	payload, err := json.Marshal(reqBody)
	require.NoError(t, err)
	t.Log("Step 1: Authorization Request")
	req := httptest.NewRequest(http.MethodPost, "/auth/authorize", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()

	assert.Equal(t, http.StatusOK, res.StatusCode)

	var body map[string]string
	require.NoError(t, json.NewDecoder(res.Body).Decode(&body))

	code := body["code"]
	redirectURI := body["redirect_uri"]
	require.NotEmpty(t, code)
	assert.Contains(t, redirectURI, "code="+code)
	assert.Contains(t, redirectURI, "state=state-xyz")

	t.Log("Verifying session created with pending consent status")
	session, err := sessionStore.FindByCode(context.Background(), code)
	require.NoError(t, err)
	assert.Equal(t, service.StatusPendingConsent, session.Status)
	assert.Equal(t, reqBody.Scopes, session.RequestedScope)

	user, err := userStore.FindByEmail(context.Background(), reqBody.Email)
	require.NoError(t, err)
	assert.Equal(t, user.ID, session.UserID)

	t.Log("Step 2: Token Request")
	tokenRequest := &models.TokenRequest{
		GrantType: "authorization_code",
		// Code:        session.Code,
		// RedirectURI: session.RedirectURI,
		ClientID: session.ClientID,
	}
	tokenPayload, err := json.Marshal(tokenRequest)
	require.NoError(t, err)

	tokenReq := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(tokenPayload))
	tokenReq.Header.Set("Content-Type", "application/json")
	tokenRec := httptest.NewRecorder()

	r.ServeHTTP(tokenRec, tokenReq)
	tokenRes := tokenRec.Result()
	defer tokenRes.Body.Close()

	assert.Equal(t, http.StatusOK, tokenRes.StatusCode)

	var tokenBody map[string]any
	require.NoError(t, json.NewDecoder(tokenRes.Body).Decode(&tokenBody))

	accessToken := tokenBody["access_token"]
	assert.NotEmpty(t, accessToken)

	t.Log("Step 3: UserInfo Request")
	userInfoReq := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)
	userInfoReq.Header.Set("Authorization", "Bearer "+accessToken.(string))
	userInfoReq.Header.Set("Content-Type", "application/json")

	userInfoRec := httptest.NewRecorder()
	r.ServeHTTP(userInfoRec, userInfoReq)
	userInfoRes := userInfoRec.Result()
	defer userInfoRes.Body.Close()

	assert.Equal(t, http.StatusOK, userInfoRes.StatusCode)

	var userInfo models.UserInfoResult
	require.NoError(t, json.NewDecoder(userInfoRes.Body).Decode(&userInfo))

	assert.Equal(t, user.Email, userInfo.Email)
	assert.Equal(t, user.FirstName, userInfo.GivenName)
	assert.Equal(t, user.LastName, userInfo.FamilyName)
	assert.Equal(t, user.ID.String(), userInfo.Sub)

	t.Log("Verifying session is updated to active status")
	session, err = sessionStore.FindByCode(context.Background(), code)
	require.NoError(t, err)
	assert.Equal(t, service.StatusActive, session.Status)

	t.Log("Verifying user stored correctly")
	users, err := userStore.ListAll(context.Background())
	require.NoError(t, err)
	assert.Len(t, users, 1)
	assert.Equal(t, user.ID, users[user.ID.String()].ID)

	t.Log("Verifying audit events recorded")
	auditEvents, err := auditStore.ListByUser(context.Background(), user.ID.String())
	require.NoError(t, err)
	assert.Len(t, auditEvents, 4) // user created, session created, tokens issued, userinfo accessed

	actions := make([]string, 0, len(auditEvents))
	for _, event := range auditEvents {
		assert.Equal(t, user.ID.String(), event.UserID)
		actions = append(actions, event.Action)
	}
	assert.ElementsMatch(t, []string{
		"user_created",
		"session_created",
		"token_issued",
		"userinfo_accessed",
	}, actions)
}

func TestConcurrentUserCreation(t *testing.T) {
	// This test would simulate multiple concurrent requests to create
	// the same user and ensure that the user store handles it correctly
	// without creating duplicate users.
	r, userStore, _, _, _ := SetupSuite(t)
	concurrentRequests := 10
	errCh := make(chan error, concurrentRequests)

	for i := 0; i < concurrentRequests; i++ {
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

	for i := 0; i < concurrentRequests; i++ {
		err := <-errCh
		require.NoError(t, err)
	}

	users, err := userStore.ListAll(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, len(users), "expected only one user to be created")
}

func TestSessionExpiryHandling(t *testing.T) {
	r, _, sessionStore, _, _ := SetupSuite(t)
	session := &models.Session{
		ID:       uuid.New(),
		UserID:   uuid.New(),
		ClientID: "client-123",
		// RedirectURI:   "https://client.app/callback",
		// Code:          "auth-code-xyz",
		// CodeExpiresAt: time.Now().Add(1 * time.Second),
		Status: service.StatusPendingConsent,
	}
	err := sessionStore.Create(context.Background(), session)
	require.NoError(t, err)

	// Wait for session to expire
	time.Sleep(2 * time.Second)

	// Attempt to exchange code for token
	tokenRequest := &models.TokenRequest{
		GrantType: "authorization_code",
		// Code:        session.Code,
		// RedirectURI: session.RedirectURI,
		ClientID: session.ClientID,
	}
	tokenPayload, err := json.Marshal(tokenRequest)
	require.NoError(t, err)

	tokenReq := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(tokenPayload))
	tokenReq.Header.Set("Content-Type", "application/json")
	tokenRec := httptest.NewRecorder()

	r.ServeHTTP(tokenRec, tokenReq)
	tokenRes := tokenRec.Result()
	defer tokenRes.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, tokenRes.StatusCode)

	var tokenBody map[string]string
	require.NoError(t, json.NewDecoder(tokenRes.Body).Decode(&tokenBody))

	assert.Equal(t, string(dErrors.CodeUnauthorized), tokenBody["error"])
}

func TestInvalidBearerTokenRejection(t *testing.T) {
	r, _, _, _, _ := SetupSuite(t)
	invalidTokens := []string{
		"",                   // Empty token
		"invalidtoken",       // Random string
		"authz_invalid_code", // Invalid code format
		"authz_expired_code", // Simulated expired code
	}

	for _, token := range invalidTokens {
		t.Run(fmt.Sprintf("Token: %s", token), func(t *testing.T) {
			userInfoReq := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)
			userInfoReq.Header.Set("Authorization", "Bearer "+token)
			userInfoReq.Header.Set("Content-Type", "application/json")

			userInfoRec := httptest.NewRecorder()
			r.ServeHTTP(userInfoRec, userInfoReq)
			userInfoRes := userInfoRec.Result()
			defer userInfoRes.Body.Close()

			assert.Equal(t, http.StatusUnauthorized, userInfoRes.StatusCode)

			var userInfoBody map[string]string
			require.NoError(t, json.NewDecoder(userInfoRes.Body).Decode(&userInfoBody))

			assert.Equal(t, string(dErrors.CodeUnauthorized), userInfoBody["error"])
		})
	}
}

func TestAdminDeleteUser(t *testing.T) {
	r, userStore, sessionStore, _, auditStore := SetupSuite(t)

	t.Log("Step 1: Create a user with a session via authorization flow")
	reqBody := models.AuthorizationRequest{
		Email:       "user-to-delete@example.com",
		ClientID:    "client-123",
		Scopes:      []string{"openid"},
		RedirectURI: "https://client.app/callback",
	}
	payload, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/authorize", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()

	assert.Equal(t, http.StatusOK, res.StatusCode)

	var authRes map[string]string
	require.NoError(t, json.NewDecoder(res.Body).Decode(&authRes))
	code := authRes["code"]
	require.NotEmpty(t, code)

	// Verify user and session were created
	user, err := userStore.FindByEmail(context.Background(), reqBody.Email)
	require.NoError(t, err)
	require.NotNil(t, user)

	session, err := sessionStore.FindByCode(context.Background(), code)
	require.NoError(t, err)
	require.NotNil(t, session)
	assert.Equal(t, user.ID, session.UserID)

	t.Log("Step 2: Delete the user via admin endpoint")
	deleteReq := httptest.NewRequest(http.MethodDelete, "/admin/auth/users/"+user.ID.String(), nil)
	deleteReq.Header.Set("X-Admin-Token", "test-admin-token")
	deleteRec := httptest.NewRecorder()

	r.ServeHTTP(deleteRec, deleteReq)
	deleteRes := deleteRec.Result()
	defer deleteRes.Body.Close()

	assert.Equal(t, http.StatusNoContent, deleteRes.StatusCode)

	t.Log("Step 3: Verify user is deleted")
	_, err = userStore.FindByID(context.Background(), user.ID)
	assert.Error(t, err, "expected error when looking up deleted user")

	t.Log("Step 4: Verify sessions are deleted")
	_, err = sessionStore.FindByID(context.Background(), session.ID)
	assert.Error(t, err, "expected error when looking up deleted session")

	t.Log("Step 5: Verify audit events recorded")
	auditEvents, err := auditStore.ListByUser(context.Background(), user.ID.String())
	require.NoError(t, err)
	// Should have: user_created, session_created, sessions_revoked, user_deleted
	assert.GreaterOrEqual(t, len(auditEvents), 4)

	actions := make([]string, 0, len(auditEvents))
	for _, event := range auditEvents {
		actions = append(actions, event.Action)
	}
	assert.Contains(t, actions, "user_deleted")
	assert.Contains(t, actions, "sessions_revoked")
}

func TestAdminDeleteUserNotFound(t *testing.T) {
	r, _, _, _, _ := SetupSuite(t)

	nonExistentUserID := uuid.New()
	deleteReq := httptest.NewRequest(http.MethodDelete, "/admin/auth/users/"+nonExistentUserID.String(), nil)
	deleteReq.Header.Set("X-Admin-Token", "test-admin-token")
	deleteRec := httptest.NewRecorder()

	r.ServeHTTP(deleteRec, deleteReq)
	deleteRes := deleteRec.Result()
	defer deleteRes.Body.Close()

	assert.Equal(t, http.StatusNotFound, deleteRes.StatusCode)

	var errBody map[string]string
	require.NoError(t, json.NewDecoder(deleteRes.Body).Decode(&errBody))
	assert.Equal(t, string(dErrors.CodeNotFound), errBody["error"])
}

func TestAdminDeleteUserInvalidUUID(t *testing.T) {
	r, _, _, _, _ := SetupSuite(t)

	deleteReq := httptest.NewRequest(http.MethodDelete, "/admin/auth/users/invalid-uuid", nil)
	deleteReq.Header.Set("X-Admin-Token", "test-admin-token")
	deleteRec := httptest.NewRecorder()

	r.ServeHTTP(deleteRec, deleteReq)
	deleteRes := deleteRec.Result()
	defer deleteRes.Body.Close()

	assert.Equal(t, http.StatusBadRequest, deleteRes.StatusCode)

	var errBody map[string]string
	require.NoError(t, json.NewDecoder(deleteRes.Body).Decode(&errBody))
	assert.Equal(t, string(dErrors.CodeBadRequest), errBody["error"])
}

func TestAdminDeleteUserUnauthorized(t *testing.T) {
	r, userStore, _, _, _ := SetupSuite(t)

	// Create a user first
	reqBody := models.AuthorizationRequest{
		Email:       "user-to-delete@example.com",
		ClientID:    "client-123",
		Scopes:      []string{"openid"},
		RedirectURI: "https://client.app/callback",
	}
	payload, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/authorize", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()

	user, err := userStore.FindByEmail(context.Background(), reqBody.Email)
	require.NoError(t, err)

	testCases := []struct {
		name        string
		adminToken  string
		expectedMsg string
	}{
		{
			name:        "wrong token",
			adminToken:  "wrong-token",
			expectedMsg: "forbidden",
		},
		{
			name:        "empty token",
			adminToken:  "",
			expectedMsg: "forbidden",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			deleteReq := httptest.NewRequest(http.MethodDelete, "/admin/auth/users/"+user.ID.String(), nil)
			if tc.adminToken != "" {
				deleteReq.Header.Set("X-Admin-Token", tc.adminToken)
			}
			deleteRec := httptest.NewRecorder()

			r.ServeHTTP(deleteRec, deleteReq)
			deleteRes := deleteRec.Result()
			defer deleteRes.Body.Close()

			assert.Equal(t, http.StatusForbidden, deleteRes.StatusCode)

			var errBody map[string]string
			require.NoError(t, json.NewDecoder(deleteRes.Body).Decode(&errBody))
			assert.Equal(t, tc.expectedMsg, errBody["error"])
		})
	}
}
