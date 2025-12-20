package service

import (
	"context"
	"time"

	"credo/internal/auth/models"
	id "credo/pkg/domain"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func (s *ServiceSuite) TestListSessions() {
	ctx := context.Background()
	userID := id.UserID(uuid.New())
	currentSessionID := id.SessionID(uuid.New())

	now := time.Now()
	activeCurrent := &models.Session{
		ID:                currentSessionID,
		UserID:            userID,
		Status: models.SessionStatusActive,
		DeviceDisplayName: "Chrome on macOS",
		CreatedAt:         now.Add(-2 * time.Hour),
		LastSeenAt:        now.Add(-1 * time.Minute),
		ExpiresAt:         now.Add(24 * time.Hour),
	}
	activeOther := &models.Session{
		ID:                id.SessionID(uuid.New()),
		UserID:            userID,
		Status: models.SessionStatusActive,
		DeviceDisplayName: "Safari on iPhone",
		CreatedAt:         now.Add(-5 * time.Hour),
		LastSeenAt:        now.Add(-30 * time.Minute),
		ExpiresAt:         now.Add(24 * time.Hour),
	}
	revoked := &models.Session{
		ID:         id.SessionID(uuid.New()),
		UserID:     userID,
		Status: models.SessionStatusRevoked,
		CreatedAt:  now.Add(-24 * time.Hour),
		LastSeenAt: now.Add(-23 * time.Hour),
		ExpiresAt:  now.Add(24 * time.Hour),
	}
	expired := &models.Session{
		ID:         id.SessionID(uuid.New()),
		UserID:     userID,
		Status: models.SessionStatusActive,
		CreatedAt:  now.Add(-48 * time.Hour),
		LastSeenAt: now.Add(-47 * time.Hour),
		ExpiresAt:  now.Add(-1 * time.Hour),
	}

	s.mockSessionStore.EXPECT().
		ListByUser(gomock.Any(), userID).
		Return([]*models.Session{activeOther, revoked, activeCurrent, expired}, nil)

	res, err := s.service.ListSessions(ctx, userID, currentSessionID)
	require.NoError(s.T(), err)
	require.Len(s.T(), res.Sessions, 2)

	assert.Equal(s.T(), activeCurrent.ID.String(), res.Sessions[0].SessionID)
	assert.True(s.T(), res.Sessions[0].IsCurrent)
	assert.Equal(s.T(), "Chrome on macOS", res.Sessions[0].Device)

	assert.Equal(s.T(), activeOther.ID.String(), res.Sessions[1].SessionID)
	assert.False(s.T(), res.Sessions[1].IsCurrent)
	assert.Equal(s.T(), "Safari on iPhone", res.Sessions[1].Device)
}
