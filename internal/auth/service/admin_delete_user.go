package service

import (
	"context"
	"errors"

	sessionStore "credo/internal/auth/store/session"
	userStore "credo/internal/auth/store/user"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	request "credo/pkg/platform/middleware/request"
)

func (s *Service) DeleteUser(ctx context.Context, userID id.UserID) error {
	if userID.IsNil() {
		return dErrors.New(dErrors.CodeBadRequest, "user ID required")
	}

	// Capture user before deletion to enrich audit events (PRD-001B)
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, userStore.ErrNotFound) {
			return dErrors.New(dErrors.CodeNotFound, "user not found")
		}
		return dErrors.Wrap(err, dErrors.CodeInternal, "failed to lookup user")
	}

	// Extract request_id for audit enrichment (PRD-001B)
	requestID := request.GetRequestID(ctx)

	if err := s.sessions.DeleteSessionsByUser(ctx, userID); err != nil {
		if !errors.Is(err, sessionStore.ErrNotFound) {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to delete user sessions")
		}
	}

	// PRD-001B: Audit events include user_id, email, and request_id
	auditAttrs := []any{
		"user_id", userID.String(),
		"email", user.Email,
	}
	if requestID != "" {
		auditAttrs = append(auditAttrs, "request_id", requestID)
	}

	s.logAudit(ctx, string(audit.EventSessionsRevoked), auditAttrs...)

	if err := s.users.Delete(ctx, userID); err != nil {
		if errors.Is(err, userStore.ErrNotFound) {
			return dErrors.New(dErrors.CodeNotFound, "user not found")
		}
		return dErrors.Wrap(err, dErrors.CodeInternal, "failed to delete user")
	}

	s.logAudit(ctx, string(audit.EventUserDeleted), auditAttrs...)

	return nil
}
