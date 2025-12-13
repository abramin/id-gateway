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
	"credo/internal/auth/device"
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
	*authCodeStore.InMemoryAuthorizationCodeStore,
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
	cfg := service.Config{
		SessionTTL:             24 * time.Hour,
		TokenTTL:               15 * time.Minute,
		AllowedRedirectSchemes: []string{"https", "http"},
		DeviceBindingEnabled:   true,
	}
	authService, _ := service.New(userStore, sessionStore, authCodeStore, refreshTokenStore,
		&cfg,
		service.WithLogger(logger),
		service.WithJWTService(jwtService),
		service.WithAuditPublisher(audit.NewPublisher(auditStore)),
	)

	router := chi.NewRouter()
	router.Use(middleware.ClientMetadata)
	authHandler := auth.New(authService, logger, "__Secure-Device-ID", 31536000)

	// Public endpoints (no auth required) - mirrors production setup
	router.Post("/auth/authorize", authHandler.HandleAuthorize)
	router.Post("/auth/token", authHandler.HandleToken)
	router.Post("/auth/revoke", authHandler.HandleRevoke)

	// Protected endpoints (auth required)
	router.Group(func(r chi.Router) {
		r.Use(middleware.RequireAuth(jwtValidator, authService, logger)) // authService implements TokenRevocationChecker
		r.Get("/auth/userinfo", authHandler.HandleUserInfo)
	})

	// Admin endpoints (admin token required)
	router.Group(func(r chi.Router) {
		r.Use(middleware.RequireAdminToken("test-admin-token", logger))
		authHandler.RegisterAdmin(r)
	})

	return router, userStore, sessionStore, authCodeStore, jwtService, auditStore
}

// TestOAuthFlow validates the complete OAuth 2.0 authorization code flow (PRD-001 FR-1, FR-2, FR-3)
func TestOAuthFlow(t *testing.T) {
	r, userStore, sessionStore, codeStore, _, auditStore := SetupSuite(t)
	uaString := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
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
	req.Header.Set("User-Agent", uaString)
	req.Header.Set("X-Real-IP", "192.168.1.1")
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

	var deviceCookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == "__Secure-Device-ID" {
			deviceCookie = c
			break
		}
	}
	require.NotNil(t, deviceCookie)
	require.NotEmpty(t, deviceCookie.Value)

	t.Log("Verifying session created with pending consent status")
	codeRecord, err := codeStore.FindByCode(context.Background(), code)
	require.NoError(t, err)
	session, err := sessionStore.FindByID(context.Background(), codeRecord.SessionID)
	require.NoError(t, err)
	assert.Equal(t, service.StatusPendingConsent, session.Status)
	assert.Equal(t, reqBody.Scopes, session.RequestedScope)
	assert.Equal(t, deviceCookie.Value, session.DeviceID)
	assert.Equal(t, device.NewService(true).ComputeFingerprint(uaString), session.DeviceFingerprintHash)

	user, err := userStore.FindByEmail(context.Background(), reqBody.Email)
	require.NoError(t, err)
	assert.Equal(t, user.ID, session.UserID)

	t.Log("Step 2: Token Request")
	tokenRequest := &models.TokenRequest{
		GrantType: "authorization_code",
		Code:      code,
		ClientID:  session.ClientID,
		// RedirectURI must match what was used at /auth/authorize
		RedirectURI: reqBody.RedirectURI,
	}
	tokenPayload, err := json.Marshal(tokenRequest)
	require.NoError(t, err)

	tokenReq := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(tokenPayload))
	tokenReq.Header.Set("Content-Type", "application/json")
	tokenReq.Header.Set("User-Agent", uaString)
	tokenReq.Header.Set("X-Real-IP", "192.168.1.1")
	tokenReq.AddCookie(deviceCookie)
	tokenRec := httptest.NewRecorder()

	r.ServeHTTP(tokenRec, tokenReq)
	tokenRes := tokenRec.Result()
	defer tokenRes.Body.Close()

	assert.Equal(t, http.StatusOK, tokenRes.StatusCode)

	var tokenBody map[string]any
	require.NoError(t, json.NewDecoder(tokenRes.Body).Decode(&tokenBody))

	accessToken := tokenBody["access_token"]
	assert.NotEmpty(t, accessToken)
	refreshToken := tokenBody["refresh_token"]
	assert.NotEmpty(t, refreshToken)

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
	codeRecord, err = codeStore.FindByCode(context.Background(), code)
	require.NoError(t, err)
	session, err = sessionStore.FindByID(context.Background(), codeRecord.SessionID)
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

// TestTokenRevocation validates token revocation flows (PRD-016 FR-3)
func TestTokenRevocation(t *testing.T) {
	r, _, sessionStore, codeStore, _, _ := SetupSuite(t)
	uaString := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	t.Run("access token revocation - session invalidated", func(t *testing.T) {
		uaString := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

		t.Log("Step 1: Authorization Request")
		reqBody := models.AuthorizationRequest{
			Email:       "revoke.access@example.com",
			ClientID:    "client-123",
			Scopes:      []string{"openid", "profile"},
			RedirectURI: "https://client.app/callback",
			State:       "state-xyz",
		}
		payload, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/auth/authorize", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", uaString)
		req.Header.Set("X-Real-IP", "192.168.1.1")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		res := rec.Result()
		defer res.Body.Close()
		require.Equal(t, http.StatusOK, res.StatusCode)

		var authBody map[string]string
		require.NoError(t, json.NewDecoder(res.Body).Decode(&authBody))
		code := authBody["code"]
		require.NotEmpty(t, code)

		var deviceCookie *http.Cookie
		for _, c := range res.Cookies() {
			if c.Name == "__Secure-Device-ID" {
				deviceCookie = c
				break
			}
		}
		require.NotNil(t, deviceCookie)

		t.Log("Step 2: Token Request")
		tokenRequest := &models.TokenRequest{
			GrantType:    "authorization_code",
			Code:         code,
			ClientID:     reqBody.ClientID,
			RedirectURI:  reqBody.RedirectURI,
			RefreshToken: "",
		}
		tokenPayload, err := json.Marshal(tokenRequest)
		require.NoError(t, err)

		tokenReq := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(tokenPayload))
		tokenReq.Header.Set("Content-Type", "application/json")
		tokenReq.Header.Set("User-Agent", uaString)
		tokenReq.Header.Set("X-Real-IP", "192.168.1.1")
		tokenReq.AddCookie(deviceCookie)
		tokenRec := httptest.NewRecorder()
		r.ServeHTTP(tokenRec, tokenReq)
		tokenRes := tokenRec.Result()
		defer tokenRes.Body.Close()
		require.Equal(t, http.StatusOK, tokenRes.StatusCode)

		var tokenBody map[string]any
		require.NoError(t, json.NewDecoder(tokenRes.Body).Decode(&tokenBody))
		accessToken := tokenBody["access_token"].(string)
		require.NotEmpty(t, accessToken)

		codeRecord, err := codeStore.FindByCode(context.Background(), code)
		require.NoError(t, err)
		session, err := sessionStore.FindByID(context.Background(), codeRecord.SessionID)
		require.NoError(t, err)
		require.Equal(t, service.StatusActive, session.Status)

		t.Log("Step 3: Revoke Access Token")
		revokePayload, err := json.Marshal(map[string]any{
			"token":           accessToken,
			"token_type_hint": "access_token",
		})
		require.NoError(t, err)
		revokeReq := httptest.NewRequest(http.MethodPost, "/auth/revoke", bytes.NewReader(revokePayload))
		revokeReq.Header.Set("Content-Type", "application/json")
		revokeRec := httptest.NewRecorder()
		r.ServeHTTP(revokeRec, revokeReq)
		revokeRes := revokeRec.Result()
		defer revokeRes.Body.Close()
		require.Equal(t, http.StatusOK, revokeRes.StatusCode)

		t.Log("Step 4: Accessing UserInfo with revoked Access Token should fail")
		userInfoReq := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)
		userInfoReq.Header.Set("Authorization", "Bearer "+accessToken)
		userInfoRec := httptest.NewRecorder()
		r.ServeHTTP(userInfoRec, userInfoReq)
		require.Equal(t, http.StatusUnauthorized, userInfoRec.Result().StatusCode)
		assert.Contains(t, userInfoRec.Body.String(), "Token has been revoked")

		t.Log("Verifying session is updated to revoked status")
		session, err = sessionStore.FindByID(context.Background(), codeRecord.SessionID)
		require.NoError(t, err)
		assert.Equal(t, service.StatusRevoked, session.Status)
		require.NotNil(t, session.RevokedAt)
	})

	t.Run("refresh token revocation - cannot refresh", func(t *testing.T) {
		t.Log("Step 1: Authorization Request")
		reqBody := models.AuthorizationRequest{
			Email:       "revoke.refresh@example.com",
			ClientID:    "client-123",
			Scopes:      []string{"openid"},
			RedirectURI: "https://client.app/callback",
			State:       "state-xyz",
		}
		payload, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/auth/authorize", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", uaString)
		req.Header.Set("X-Real-IP", "192.168.1.1")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		res := rec.Result()
		defer res.Body.Close()
		require.Equal(t, http.StatusOK, res.StatusCode)

		var authBody map[string]string
		require.NoError(t, json.NewDecoder(res.Body).Decode(&authBody))
		code := authBody["code"]
		require.NotEmpty(t, code)

		var deviceCookie *http.Cookie
		for _, c := range res.Cookies() {
			if c.Name == "__Secure-Device-ID" {
				deviceCookie = c
				break
			}
		}
		require.NotNil(t, deviceCookie)

		t.Log("Step 2: Token Request")
		tokenRequest := &models.TokenRequest{
			GrantType:   "authorization_code",
			Code:        code,
			ClientID:    reqBody.ClientID,
			RedirectURI: reqBody.RedirectURI,
		}
		tokenPayload, err := json.Marshal(tokenRequest)
		require.NoError(t, err)

		tokenReq := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(tokenPayload))
		tokenReq.Header.Set("Content-Type", "application/json")
		tokenReq.Header.Set("User-Agent", uaString)
		tokenReq.Header.Set("X-Real-IP", "192.168.1.1")
		tokenReq.AddCookie(deviceCookie)
		tokenRec := httptest.NewRecorder()
		r.ServeHTTP(tokenRec, tokenReq)
		tokenRes := tokenRec.Result()
		defer tokenRes.Body.Close()
		require.Equal(t, http.StatusOK, tokenRes.StatusCode)

		var tokenBody map[string]any
		require.NoError(t, json.NewDecoder(tokenRes.Body).Decode(&tokenBody))
		refreshToken := tokenBody["refresh_token"].(string)
		require.NotEmpty(t, refreshToken)

		t.Log("Step 3: Revoke Refresh Token")
		revokePayload, err := json.Marshal(map[string]any{
			"token":           refreshToken,
			"token_type_hint": "refresh_token",
		})
		require.NoError(t, err)
		revokeReq := httptest.NewRequest(http.MethodPost, "/auth/revoke", bytes.NewReader(revokePayload))
		revokeReq.Header.Set("Content-Type", "application/json")
		revokeRec := httptest.NewRecorder()
		r.ServeHTTP(revokeRec, revokeReq)
		revokeRes := revokeRec.Result()
		defer revokeRes.Body.Close()
		require.Equal(t, http.StatusOK, revokeRes.StatusCode)

		t.Log("Step 4: Attempt to refresh with revoked token should fail")
		refreshReqBody := &models.TokenRequest{
			GrantType:    "refresh_token",
			RefreshToken: refreshToken,
			ClientID:     reqBody.ClientID,
		}
		refreshPayload, err := json.Marshal(refreshReqBody)
		require.NoError(t, err)
		refreshReq := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(refreshPayload))
		refreshReq.Header.Set("Content-Type", "application/json")
		refreshRec := httptest.NewRecorder()
		r.ServeHTTP(refreshRec, refreshReq)
		require.Equal(t, http.StatusUnauthorized, refreshRec.Result().StatusCode)
		assert.Contains(t, refreshRec.Body.String(), "unauthorized")
	})
}

// TestConcurrentUserCreation validates race condition handling (PRD-001 Integration Test)
func TestConcurrentUserCreation(t *testing.T) {
	// This test would simulate multiple concurrent requests to create
	// the same user and ensure that the user store handles it correctly
	// without creating duplicate users.
	r, userStore, _, _, _, _ := SetupSuite(t)
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

// TestAdminDeleteUser validates admin user deletion flows (PRD-001B)
func TestAdminDeleteUser(t *testing.T) {
	r, userStore, sessionStore, codeStore, _, auditStore := SetupSuite(t)

	t.Run("happy path - user and sessions deleted", func(t *testing.T) {
		t.Log("Step 1: Create user and session")
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
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("X-Real-IP", "192.168.1.1")
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

		codeRecord, err := codeStore.FindByCode(context.Background(), code)
		require.NoError(t, err)
		session, err := sessionStore.FindByID(context.Background(), codeRecord.SessionID)
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
	})

	t.Run("user not found - 404", func(t *testing.T) {
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
	})

	t.Run("invalid UUID - 400", func(t *testing.T) {
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
	})

	t.Run("unauthorized - 403", func(t *testing.T) {
		// Create a user first
		reqBody := models.AuthorizationRequest{
			Email:       "user-for-auth-test@example.com",
			ClientID:    "client-123",
			Scopes:      []string{"openid"},
			RedirectURI: "https://client.app/callback",
		}
		payload, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/auth/authorize", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("X-Real-IP", "192.168.1.1")
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
	})
}
