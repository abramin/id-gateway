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

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"id-gateway/internal/auth/models"
	"id-gateway/internal/auth/service"
	"id-gateway/internal/auth/store"
	"id-gateway/internal/platform/middleware"
	httptransport "id-gateway/internal/transport/http"
)

func TestAuthorizeIntegration(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	userStore := store.NewInMemoryUserStore()
	sessionStore := store.NewInMemorySessionStore()
	svc := service.NewService(userStore, sessionStore, 15*time.Minute)

	handler := httptransport.NewAuthHandler(svc, logger)
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	handler.Register(r)

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

	sessionID := body["session_id"]
	redirectURI := body["redirect_uri"]
	require.NotEmpty(t, sessionID)
	require.Contains(t, redirectURI, "session_id="+sessionID)
	require.Contains(t, redirectURI, "state=state-xyz")

	session, err := sessionStore.FindByID(context.Background(), uuid.MustParse(sessionID))
	require.NoError(t, err)
	require.Equal(t, service.StatusPendingConsent, session.Status)
	require.Equal(t, reqBody.Scopes, session.RequestedScope)

	user, err := userStore.FindByEmail(context.Background(), reqBody.Email)
	require.NoError(t, err)
	require.Equal(t, user.ID, session.UserID)
}
