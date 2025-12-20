package service

import (
	"context"
	"sort"
	"time"

	"credo/internal/auth/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
)

func (s *Service) ListSessions(ctx context.Context, userID id.UserID, currentSessionID id.SessionID) (*models.SessionsResult, error) {
	if userID.IsNil() {
		return nil, dErrors.New(dErrors.CodeUnauthorized, "user ID required")
	}
	// Note: currentSessionID can be nil (zero value) if caller doesn't have a current session

	sessions, err := s.sessions.ListByUser(ctx, userID)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to list sessions")
	}

	now := time.Now()
	active := make([]*models.Session, 0, len(sessions))
	for _, session := range sessions {
		if session == nil {
			continue
		}
		if session.Status != models.SessionStatusActive {
			continue
		}
		if session.ExpiresAt.Before(now) {
			continue
		}
		active = append(active, session)
	}

	sort.Slice(active, func(i, j int) bool {
		return active[i].LastSeenAt.After(active[j].LastSeenAt)
	})

	out := make([]models.SessionSummary, 0, len(active))
	for _, session := range active {
		deviceName := session.DeviceDisplayName
		if deviceName == "" {
			deviceName = "Unknown device"
		}

		out = append(out, models.SessionSummary{
			SessionID:    session.ID.String(),
			Device:       deviceName,
			Location:     session.ApproximateLocation,
			CreatedAt:    session.CreatedAt,
			LastActivity: session.LastSeenAt,
			IsCurrent:    session.ID == currentSessionID,
		})
	}

	return &models.SessionsResult{Sessions: out}, nil
}
