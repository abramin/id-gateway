package service

import (
	"context"

	"credo/internal/audit"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
)

// RevokeSession implements PRD-016 FR-5: revoke a specific session owned by the user.
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
