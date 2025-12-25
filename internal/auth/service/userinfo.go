package service

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"credo/internal/auth/models"
	sessionStore "credo/internal/auth/store/session"
	userStore "credo/internal/auth/store/user"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
)

// UserInfo retrieves user information based on the provided session ID.
// It validates the session, checks its activity status, and fetches the associated user.
// If successful, it returns a UserInfoResult containing user details.
func (s *Service) UserInfo(ctx context.Context, sessionID string) (*models.UserInfoResult, error) {
	if sessionID == "" {
		s.authFailure(ctx, "missing_session_id", false)
		return nil, dErrors.New(dErrors.CodeUnauthorized, "missing or invalid session")
	}

	parsedSessionID, err := uuid.Parse(sessionID)
	if err != nil {
		s.authFailure(ctx, "invalid_session_id_format", false,
			"session_id", sessionID,
			"error", err,
		)
		return nil, dErrors.New(dErrors.CodeUnauthorized, "invalid session ID")
	}

	session, err := s.sessions.FindByID(ctx, id.SessionID(parsedSessionID))
	if errors.Is(err, sessionStore.ErrNotFound) {
		s.authFailure(ctx, "session_not_found", false,
			"session_id", parsedSessionID.String(),
		)
		return nil, dErrors.New(dErrors.CodeUnauthorized, "session not found")
	}
	if err != nil {
		s.authFailure(ctx, "session_lookup_failed", true,
			"session_id", parsedSessionID.String(),
			"error", err,
		)
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to find session")
	}

	if !session.IsActive() {
		s.authFailure(ctx, "session_not_active", false,
			"session_id", parsedSessionID.String(),
			"status", session.Status.String(),
		)
		return nil, dErrors.New(dErrors.CodeUnauthorized, "session not active")
	}

	user, err := s.users.FindByID(ctx, session.UserID)
	if errors.Is(err, userStore.ErrNotFound) {
		s.authFailure(ctx, "user_not_found", false,
			"session_id", parsedSessionID.String(),
			"user_id", session.UserID.String(),
		)
		return nil, dErrors.New(dErrors.CodeUnauthorized, "user not found")
	}
	if err != nil {
		s.authFailure(ctx, "user_lookup_failed", true,
			"session_id", parsedSessionID.String(),
			"user_id", session.UserID.String(),
			"error", err,
		)
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to find user")
	}

	userInfo := &models.UserInfoResult{
		Sub:           user.ID.String(),
		Email:         user.Email,
		EmailVerified: user.Verified,
		GivenName:     user.FirstName,
		FamilyName:    user.LastName,
		Name:          user.FirstName + " " + user.LastName,
	}
	s.logAudit(ctx, string(audit.EventUserInfoAccessed),
		"user_id", user.ID.String(),
		"session_id", session.ID.String(),
	)

	return userInfo, nil
}
