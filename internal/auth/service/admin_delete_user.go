package service

import (
	"context"
	"errors"

	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	"credo/pkg/platform/sentinel"
)

// DeleteUser deletes a user and revokes their sessions as an admin operation.
func (s *Service) DeleteUser(ctx context.Context, userID id.UserID) error {
	if userID.IsNil() {
		return dErrors.New(dErrors.CodeBadRequest, "user ID required")
	}

	// Capture user before deletion to enrich audit events
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sentinel.ErrNotFound) {
			return dErrors.New(dErrors.CodeNotFound, "user not found")
		}
		return dErrors.Wrap(err, dErrors.CodeInternal, "failed to lookup user")
	}

	if err := s.sessions.DeleteSessionsByUser(ctx, userID); err != nil {
		if !errors.Is(err, sentinel.ErrNotFound) {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to delete user sessions")
		}
	}

	auditAttrs := []any{
		"user_id", userID.String(),
		"email", user.Email,
	}

	s.logAudit(ctx, string(audit.EventSessionsRevoked), auditAttrs...)

	if err := s.users.Delete(ctx, userID); err != nil {
		if errors.Is(err, sentinel.ErrNotFound) {
			return dErrors.New(dErrors.CodeNotFound, "user not found")
		}
		return dErrors.Wrap(err, dErrors.CodeInternal, "failed to delete user")
	}

	s.logAudit(ctx, string(audit.EventUserDeleted), auditAttrs...)

	return nil
}
