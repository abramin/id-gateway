package service

import (
	"context"
	"sort"

	"credo/internal/auth/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/requestcontext"
)

// ListSessions returns active sessions for a user, ordered by recent activity.
// It filters out inactive or expired sessions and marks the current session.
func (s *Service) ListSessions(ctx context.Context, userID id.UserID, currentSessionID id.SessionID) (*models.SessionsResult, error) {
	if userID.IsNil() {
		return nil, dErrors.New(dErrors.CodeUnauthorized, "user ID required")
	}
	// Note: currentSessionID can be nil (zero value) if caller doesn't have a current session
	sessions, err := s.sessions.ListByUser(ctx, userID)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to list sessions")
	}

	now := requestcontext.Now(ctx)
	active := make([]*models.Session, 0, len(sessions))
	for _, session := range sessions {
		if session == nil {
			continue
		}
		if !session.IsActive() {
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
		binding := session.GetDeviceBinding()
		out = append(out, models.SessionSummary{
			SessionID:    session.ID.String(),
			Device:       binding.DisplayNameOrDefault(),
			Location:     binding.ApproximateLocation,
			CreatedAt:    session.CreatedAt,
			LastActivity: session.LastSeenAt,
			IsCurrent:    session.ID == currentSessionID,
			Status:       session.Status.String(),
		})
	}

	return &models.SessionsResult{Sessions: out}, nil
}
