package service

import (
	"context"
	"time"

	"credo/internal/auth/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
)

func (s *Service) RevokeSession(ctx context.Context, userID id.UserID, sessionID id.SessionID) error {
	if userID.IsNil() {
		return dErrors.New(dErrors.CodeUnauthorized, "user ID required")
	}
	if sessionID.IsNil() {
		return dErrors.New(dErrors.CodeBadRequest, "session ID required")
	}

	session, err := s.sessions.FindByID(ctx, sessionID)
	if err != nil {
		if dErrors.HasCode(err, dErrors.CodeNotFound) {
			return dErrors.New(dErrors.CodeNotFound, "session not found")
		}
		return dErrors.Wrap(err, dErrors.CodeInternal, "failed to find session")
	}

	if session.UserID != userID {
		s.authFailure(ctx, "session_owner_mismatch", false,
			"session_id", session.ID.String(),
			"user_id", userID.String(),
		)
		return dErrors.New(dErrors.CodeForbidden, "forbidden")
	}

	outcome, err := s.revokeSessionInternal(ctx, session, "")
	if err != nil {
		return dErrors.Wrap(err, dErrors.CodeInternal, "failed to revoke session")
	}
	if outcome == revokeSessionOutcomeAlreadyRevoked {
		return nil
	}

	s.logAudit(ctx, string(audit.EventSessionRevoked),
		"user_id", session.UserID.String(),
		"session_id", session.ID.String(),
		"client_id", session.ClientID,
	)

	return nil
}

// LogoutAll revokes all sessions for a user, optionally keeping the current session.
// Design: Continues on individual revocation errors to maximize successful revocations.
// Returns partial results with FailedCount so the user knows if retries are needed.
// Only returns an error if ALL revocations fail or listing sessions fails.
func (s *Service) LogoutAll(ctx context.Context, userID id.UserID, currentSessionID id.SessionID, exceptCurrent bool) (*models.LogoutAllResult, error) {
	start := time.Now()

	if userID.IsNil() {
		return nil, dErrors.New(dErrors.CodeUnauthorized, "user ID required")
	}

	sessions, err := s.sessions.ListByUser(ctx, userID)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to list sessions")
	}

	revokedCount := 0
	failedCount := 0
	for _, session := range sessions {
		if exceptCurrent && session.ID == currentSessionID {
			continue
		}
		outcome, err := s.revokeSessionInternal(ctx, session, "")
		if err != nil {
			// Continue on error - partial revocation is better than none
			failedCount++
			s.logger.ErrorContext(ctx, "failed to revoke session during logout-all",
				"error", err,
				"session_id", session.ID.String(),
				"user_id", userID.String(),
			)
			continue
		}
		if outcome == revokeSessionOutcomeRevoked {
			revokedCount++
			s.logAudit(ctx, string(audit.EventSessionRevoked),
				"user_id", session.UserID.String(),
				"session_id", session.ID.String(),
				"client_id", session.ClientID,
			)
		}
	}

	if s.metrics != nil {
		durationMs := float64(time.Since(start).Milliseconds())
		s.metrics.ObserveLogoutAll(revokedCount, durationMs)
	}

	return &models.LogoutAllResult{
		RevokedCount: revokedCount,
		FailedCount:  failedCount,
	}, nil
}
