package service

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"credo/internal/audit"
	sessionStore "credo/internal/auth/store/session"
	userStore "credo/internal/auth/store/user"
	dErrors "credo/pkg/domain-errors"
)

func (s *Service) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	_, err := s.users.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, userStore.ErrNotFound) {
			return dErrors.New(dErrors.CodeNotFound, "user not found")
		}
		return dErrors.Wrap(err, dErrors.CodeInternal, "failed to lookup user")
	}

	if err := s.sessions.DeleteSessionsByUser(ctx, userID); err != nil {
		if !errors.Is(err, sessionStore.ErrNotFound) {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to delete user sessions")
		}
	}
	s.logAudit(ctx, string(audit.EventSessionsRevoked),
		"user_id", userID.String(),
	)

	if err := s.users.Delete(ctx, userID); err != nil {
		if errors.Is(err, userStore.ErrNotFound) {
			return dErrors.New(dErrors.CodeNotFound, "user not found")
		}
		return dErrors.Wrap(err, dErrors.CodeInternal, "failed to delete user")
	}

	s.logAudit(ctx, string(audit.EventUserDeleted),
		"user_id", userID.String(),
	)

	return nil
}
