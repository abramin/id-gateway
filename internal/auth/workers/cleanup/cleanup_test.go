package cleanup

import (
	"context"
	"testing"
	"time"

	"credo/internal/auth/models"
	authCodeStore "credo/internal/auth/store/authorization-code"
	refreshtoken "credo/internal/auth/store/refresh-token"
	sessionStore "credo/internal/auth/store/session"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestCleanupService_RunOnce_Integration(t *testing.T) {
	ctx := context.Background()

	sessions := sessionStore.New()
	codes := authCodeStore.New()
	refreshTokens := refreshtoken.New()

	expiredSessionID := id.SessionID(uuid.New())
	expiredSession := &models.Session{
		ID:         expiredSessionID,
		UserID:     id.UserID(uuid.New()),
		ClientID:   id.ClientID(uuid.New()),
		Status:     "active",
		CreatedAt:  time.Now().Add(-48 * time.Hour),
		ExpiresAt:  time.Now().Add(-1 * time.Hour),
		LastSeenAt: time.Now(),
	}
	require.NoError(t, sessions.Create(ctx, expiredSession))

	expiredCode := &models.AuthorizationCodeRecord{
		ID:          uuid.New(),
		Code:        "authz_expired",
		SessionID:   expiredSessionID,
		RedirectURI: "https://client.app/callback",
		ExpiresAt:   time.Now().Add(-1 * time.Minute),
		CreatedAt:   time.Now().Add(-10 * time.Minute),
		Used:        false,
	}
	require.NoError(t, codes.Create(ctx, expiredCode))

	expiredRefresh := &models.RefreshTokenRecord{
		ID:        uuid.New(),
		Token:     "ref_expired",
		SessionID: expiredSessionID,
		CreatedAt: time.Now().Add(-48 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
		Used:      false,
	}
	require.NoError(t, refreshTokens.Create(ctx, expiredRefresh))

	usedRefresh := &models.RefreshTokenRecord{
		ID:        uuid.New(),
		Token:     "ref_used",
		SessionID: expiredSessionID,
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Used:      true,
	}
	require.NoError(t, refreshTokens.Create(ctx, usedRefresh))

	svc, err := New(sessions, codes, refreshTokens, WithCleanupInterval(10*time.Second))
	require.NoError(t, err)

	res, err := svc.RunOnce(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, res.DeletedAuthorizationCodes)
	require.Equal(t, 1, res.DeletedRefreshTokens)
	require.Equal(t, 1, res.DeletedUsedRefreshTokens)
	require.Equal(t, 1, res.DeletedSessions)

	// Verify expired artifacts are actually removed
	_, err = codes.FindByCode(ctx, expiredCode.Code)
	require.ErrorIs(t, err, sentinel.ErrNotFound)

	_, err = refreshTokens.Find(ctx, expiredRefresh.Token)
	require.ErrorIs(t, err, sentinel.ErrNotFound)

	allSessions, err := sessions.ListAll(ctx)
	require.NoError(t, err)
	require.NotContains(t, allSessions, expiredSessionID)
}
