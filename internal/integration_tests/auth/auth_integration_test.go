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

	"id-gateway/internal/auth/models"
	"id-gateway/internal/auth/service"
	"id-gateway/internal/auth/store"
	jwttoken "id-gateway/internal/jwt_token"
	"id-gateway/internal/platform/middleware"
	httptransport "id-gateway/internal/transport/http"
	dErrors "id-gateway/pkg/domain-errors"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func SetupSuite(t *testing.T) (*chi.Mux, *store.InMemoryUserStore, *store.InMemorySessionStore, *jwttoken.JWTService) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	userStore := store.NewInMemoryUserStore()
	sessionStore := store.NewInMemorySessionStore()
	jwtService := jwttoken.NewJWTService(
		"test-secret-key",
		"id-gateway",
		"id-gateway-client",
		15*time.Minute,
	)
	jwtValidator := jwttoken.NewJWTServiceAdapter(jwtService)
	authService := service.NewService(userStore, sessionStore, 5*time.Minute,
		service.WithLogger(logger),
		service.WithJWTService(jwtService),
	)

	router := chi.NewRouter()
	authHandler := httptransport.NewAuthHandler(authService, logger, false, nil)

	// Public endpoints (no auth required) - mirrors production setup
	router.Post("/auth/authorize", authHandler.HandleAuthorize)
	router.Post("/auth/token", authHandler.HandleToken)

	// Protected endpoints (auth required)
	router.Group(func(r chi.Router) {
		r.Use(middleware.RequireAuth(jwtValidator, logger))
		r.Get("/auth/userinfo", authHandler.HandleUserInfo)
	})

	return router, userStore, sessionStore, jwtService
}

func TestCompleteAuthFlow(t *testing.T) {
	r, userStore, sessionStore, _ := SetupSuite(t)
	reqBody := models.AuthorizationRequest{
		Email:       "jane.doe@example.com",
		ClientID:    "client-123",
		Scopes:      []string{"openid", "profile"},
		RedirectURI: "https://client.app/callback",
		State:       "state-xyz",
	}
	payload, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/authorize", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()

	require.Equal(t, http.StatusOK, res.StatusCode)

	var body map[string]string
	require.NoError(t, json.NewDecoder(res.Body).Decode(&body))

	code := body["code"]
	redirectURI := body["redirect_uri"]
	require.NotEmpty(t, code)
	require.Contains(t, redirectURI, "code="+code)
	require.Contains(t, redirectURI, "state=state-xyz")

	session, err := sessionStore.FindByCode(context.Background(), code)
	require.NoError(t, err)
	require.Equal(t, service.StatusPendingConsent, session.Status)
	require.Equal(t, reqBody.Scopes, session.RequestedScope)

	user, err := userStore.FindByEmail(context.Background(), reqBody.Email)
	require.NoError(t, err)
	require.Equal(t, user.ID, session.UserID)

	// Exchange code for token
	tokenRequest := &models.TokenRequest{
		GrantType:   "authorization_code",
		Code:        session.Code,
		RedirectURI: session.RedirectURI,
		ClientID:    session.ClientID,
	}
	tokenPayload, err := json.Marshal(tokenRequest)
	require.NoError(t, err)

	tokenReq := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(tokenPayload))
	tokenReq.Header.Set("Content-Type", "application/json")
	tokenRec := httptest.NewRecorder()

	r.ServeHTTP(tokenRec, tokenReq)
	tokenRes := tokenRec.Result()
	defer tokenRes.Body.Close()

	require.Equal(t, http.StatusOK, tokenRes.StatusCode)

	var tokenBody map[string]any
	require.NoError(t, json.NewDecoder(tokenRes.Body).Decode(&tokenBody))

	accessToken := tokenBody["access_token"]
	require.NotEmpty(t, accessToken)

	// Use token to get user info
	userInfoReq := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)
	userInfoReq.Header.Set("Authorization", "Bearer "+accessToken.(string))
	userInfoReq.Header.Set("Content-Type", "application/json")

	userInfoRec := httptest.NewRecorder()
	r.ServeHTTP(userInfoRec, userInfoReq)
	userInfoRes := userInfoRec.Result()
	defer userInfoRes.Body.Close()

	require.Equal(t, http.StatusOK, userInfoRes.StatusCode)

	var userInfo models.UserInfoResult
	require.NoError(t, json.NewDecoder(userInfoRes.Body).Decode(&userInfo))

	require.Equal(t, user.Email, userInfo.Email)
	require.Equal(t, user.FirstName, userInfo.GivenName)
	require.Equal(t, user.LastName, userInfo.FamilyName)
}

// - [ ] Test concurrent user creation (race conditions)
func TestConcurrentUserCreation(t *testing.T) {
	// This test would simulate multiple concurrent requests to create
	// the same user and ensure that the user store handles it correctly
	// without creating duplicate users.
	r, userStore, _, _ := SetupSuite(t)
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
	require.Equal(t, 1, len(users), "expected only one user to be created")
}

// - [ ] Test session expiry handling
func TestSessionExpiryHandling(t *testing.T) {
	r, _, sessionStore, _ := SetupSuite(t)
	session := &models.Session{
		ID:            uuid.New(),
		UserID:        uuid.New(),
		ClientID:      "client-123",
		RedirectURI:   "https://client.app/callback",
		Code:          "auth-code-xyz",
		CodeExpiresAt: time.Now().Add(1 * time.Second),
		Status:        service.StatusPendingConsent,
	}
	err := sessionStore.Save(context.Background(), session)
	require.NoError(t, err)

	// Wait for session to expire
	time.Sleep(2 * time.Second)

	// Attempt to exchange code for token
	tokenRequest := &models.TokenRequest{
		GrantType:   "authorization_code",
		Code:        session.Code,
		RedirectURI: session.RedirectURI,
		ClientID:    session.ClientID,
	}
	tokenPayload, err := json.Marshal(tokenRequest)
	require.NoError(t, err)

	tokenReq := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(tokenPayload))
	tokenReq.Header.Set("Content-Type", "application/json")
	tokenRec := httptest.NewRecorder()

	r.ServeHTTP(tokenRec, tokenReq)
	tokenRes := tokenRec.Result()
	defer tokenRes.Body.Close()

	require.Equal(t, http.StatusUnauthorized, tokenRes.StatusCode)

	var tokenBody map[string]string
	require.NoError(t, json.NewDecoder(tokenRes.Body).Decode(&tokenBody))

	assert.Equal(t, string(dErrors.CodeUnauthorized), tokenBody["error"])
}

func TestInvalidBearerTokenRejection(t *testing.T) {
	r, _, _, _ := SetupSuite(t)
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
