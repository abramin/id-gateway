package auth

import (
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

func TestTokenIntegration_HappyPath(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	userStore := store.NewInMemoryUserStore()
	sessionStore := store.NewInMemorySessionStore()
	svc := service.NewService(userStore, sessionStore, 15*time.Minute)

	handler := httptransport.NewAuthHandler(svc, logger)
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	handler.Register(r)
	// Setup stores, services, and handlers here...

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
	err := sessionStore.Save(ctx, session)
	require.NoError(t, err)

	userInfo := &models.User{
		ID:        session.UserID,
		Email:     "user@example.com",
		FirstName: "Test",
		LastName:  "User",
		Verified:  true,
	}
	err = userStore.Save(ctx, userInfo)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer at_sess_"+session.ID.String())
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	res := rr.Result()
	defer res.Body.Close()

	require.Equal(t, http.StatusOK, res.StatusCode)

	var userInfoRes map[string]interface{}
	err = json.NewDecoder(res.Body).Decode(&userInfoRes)
	require.NoError(t, err)

	assert.Equal(t, userInfo.Email, userInfoRes["email"])
	assert.Equal(t, userInfo.FirstName, userInfoRes["first_name"])
	assert.Equal(t, userInfo.LastName, userInfoRes["last_name"])
	assert.True(t, userInfoRes["verified"].(bool))
	// Define test cases...

	// Run test cases...
}
