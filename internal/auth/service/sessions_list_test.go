package service

import (
	"context"
	"time"

	"credo/internal/auth/models"
	id "credo/pkg/domain"

	"github.com/google/uuid"
	"go.uber.org/mock/gomock"
)

// AGENTS.MD JUSTIFICATION: Session listing filters/sorting and current-session flag
// are internal formatting details not covered by feature tests.
func (s *ServiceSuite) TestSessionListing_FiltersAndMarksCurrent() {
	ctx := context.Background()
	userID := id.UserID(uuid.New())
	currentSessionID := id.SessionID(uuid.New())

	now := time.Now()
	activeCurrent := &models.Session{
		ID:                currentSessionID,
		UserID:            userID,
		Status:            models.SessionStatusActive,
		DeviceDisplayName: "Chrome on macOS",
		CreatedAt:         now.Add(-2 * time.Hour),
		LastSeenAt:        now.Add(-1 * time.Minute),
		ExpiresAt:         now.Add(24 * time.Hour),
	}
	activeOther := &models.Session{
		ID:                id.SessionID(uuid.New()),
		UserID:            userID,
		Status:            models.SessionStatusActive,
		DeviceDisplayName: "Safari on iPhone",
		CreatedAt:         now.Add(-5 * time.Hour),
		LastSeenAt:        now.Add(-30 * time.Minute),
		ExpiresAt:         now.Add(24 * time.Hour),
	}
	revoked := &models.Session{
		ID:         id.SessionID(uuid.New()),
		UserID:     userID,
		Status:     models.SessionStatusRevoked,
		CreatedAt:  now.Add(-24 * time.Hour),
		LastSeenAt: now.Add(-23 * time.Hour),
		ExpiresAt:  now.Add(24 * time.Hour),
	}
	expired := &models.Session{
		ID:         id.SessionID(uuid.New()),
		UserID:     userID,
		Status:     models.SessionStatusActive,
		CreatedAt:  now.Add(-48 * time.Hour),
		LastSeenAt: now.Add(-47 * time.Hour),
		ExpiresAt:  now.Add(-1 * time.Hour),
	}

	s.mockSessionStore.EXPECT().
		ListByUser(gomock.Any(), userID).
		Return([]*models.Session{activeOther, revoked, activeCurrent, expired}, nil)

	res, err := s.service.ListSessions(ctx, userID, currentSessionID)
	s.Require().NoError(err)
	s.Require().Len(res.Sessions, 2)

	s.Equal(activeCurrent.ID.String(), res.Sessions[0].SessionID)
	s.True(res.Sessions[0].IsCurrent)
	s.Equal("Chrome on macOS", res.Sessions[0].Device)

	s.Equal(activeOther.ID.String(), res.Sessions[1].SessionID)
	s.False(res.Sessions[1].IsCurrent)
	s.Equal("Safari on iPhone", res.Sessions[1].Device)
}
