package auth

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

	"id-gateway/internal/auth/models"
	"id-gateway/internal/auth/service"
	"id-gateway/internal/auth/store"
	"id-gateway/internal/platform/middleware"
	httptransport "id-gateway/internal/transport/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenIntegration(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	userStore := store.NewInMemoryUserStore()
	sessionStore := store.NewInMemorySessionStore()
	svc := service.NewService(userStore, sessionStore, 15*time.Minute)

	handler := httptransport.NewAuthHandler(svc, logger)
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	handler.Register(r)

	session := &models.Session{
		ID:             uuid.New(),
		UserID:         uuid.New(),
		ClientID:       "client-123",
		Code:           "valid-auth-code",
		ExpiresAt:      time.Now().Add(10 * time.Minute),
		CodeExpiresAt:  time.Now().Add(10 * time.Minute),
		CreatedAt:      time.Now().Add(-15 * time.Minute),
		RequestedScope: []string{"openid", "profile"},
		Status:         service.StatusPendingConsent,
		CodeUsed:       false,
		RedirectURI:    "https://client.app/callback",
	}
	err := sessionStore.Save(context.Background(), session)
	require.NoError(t, err)

	tokenRequest := &models.TokenRequest{
		GrantType:   "authorization_code",
		Code:        "valid-auth-code",
		RedirectURI: session.RedirectURI,
		ClientID:    session.ClientID,
	}
	payload, err := json.Marshal(tokenRequest)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()

	require.Equal(t, http.StatusOK, res.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(res.Body).Decode(&body))

	accessToken := body["access_token"]
	idToken := body["id_token"]
	expiresIn := body["expires_in"]
	assert.NotEmpty(t, accessToken)
	assert.NotEmpty(t, idToken)
	assert.Greater(t, int64(expiresIn.(float64)), int64(0))
}

// table tests for error scaenarios can be added here
func TestTokenIntegrationErrors(t *testing.T) {
	tests := []struct {
		name       string
		request    *models.TokenRequest
		statusCode int
	}{
		{
			name: "invalid grant_type",
			request: &models.TokenRequest{
				GrantType:   "invalid_grant",
				Code:        "some-code",
				RedirectURI: "https://client.app/callback",
				ClientID:    "client-123",
			},
			statusCode: http.StatusBadRequest,
		},
		{
			name: "missing code",
			request: &models.TokenRequest{
				GrantType:   "authorization_code",
				Code:        "",
				RedirectURI: "https://client.app/callback",
				ClientID:    "client-123",
			},
			statusCode: http.StatusBadRequest,
		},
		{
			name: "missing redirect_uri",
			request: &models.TokenRequest{
				GrantType:   "authorization_code",
				Code:        "some-code",
				RedirectURI: "",
				ClientID:    "client-123",
			},
			statusCode: http.StatusBadRequest,
		},
		{
			name: "missing client_id",
			request: &models.TokenRequest{
				GrantType:   "authorization_code",
				Code:        "some-code",
				RedirectURI: "https://client.app/callback",
				ClientID:    "",
			},
			statusCode: http.StatusBadRequest,
		},
		{
			name: "expired code",
			request: &models.TokenRequest{
				GrantType:   "authorization_code",
				Code:        "expired-auth-code",
				RedirectURI: "https://client.app/callback",
				ClientID:    "client-123",
			},
			statusCode: http.StatusUnauthorized,
		},
		{
			name: "redirect_uri mismatch",
			request: &models.TokenRequest{
				GrantType:   "authorization_code",
				Code:        "some-code",
				RedirectURI: "https://malicious.app/callback",
				ClientID:    "client-123",
			},
			statusCode: http.StatusUnauthorized,
		},
		{
			name: "client_id mismatch",
			request: &models.TokenRequest{
				GrantType:   "authorization_code",
				Code:        "some-code",
				RedirectURI: "https://client.app/callback",
				ClientID:    "wrong-client",
			},
			statusCode: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			userStore := store.NewInMemoryUserStore()
			sessionStore := store.NewInMemorySessionStore()
			svc := service.NewService(userStore, sessionStore, 15*time.Minute)

			handler := httptransport.NewAuthHandler(svc, logger)
			r := chi.NewRouter()
			r.Use(middleware.RequestID)
			handler.Register(r)

			payload, err := json.Marshal(tt.request)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			r.ServeHTTP(rec, req)
			res := rec.Result()
			defer res.Body.Close()

			assert.Equal(t, tt.statusCode, res.StatusCode)
		})
	}
}
