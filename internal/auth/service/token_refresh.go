package service

import (
	"context"
	"time"

	"credo/internal/audit"
	"credo/internal/auth/models"
	dErrors "credo/pkg/domain-errors"
)

func (s *Service) refreshWithRefreshToken(ctx context.Context, req *models.TokenRequest) (*models.TokenResult, error) {
	refreshRecord, err := s.refreshTokens.Find(ctx, req.RefreshToken)
	if err != nil {
		if dErrors.Is(err, dErrors.CodeNotFound) {
			s.authFailure(ctx, "refresh_token_not_found", false,
				"client_id", req.ClientID,
			)
			return nil, dErrors.New(dErrors.CodeUnauthorized, "invalid refresh token")
		}
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to find refresh token")
	}

	// TODO:
	// “Reused refresh token → revoke entire session family”: no —
	// reuse returns 401 but does not revoke the session (or its refresh tokens).
	if refreshRecord.Used {
		s.authFailure(ctx, "refresh_token_reused", false,
			"client_id", req.ClientID,
			"session_id", refreshRecord.SessionID.String(),
		)
		return nil, dErrors.New(dErrors.CodeUnauthorized, "invalid refresh token")
	}

	if time.Now().After(refreshRecord.ExpiresAt) {
		s.authFailure(ctx, "refresh_token_expired", false,
			"client_id", req.ClientID,
			"session_id", refreshRecord.SessionID.String(),
		)
		return nil, dErrors.New(dErrors.CodeUnauthorized, "refresh token expired")
	}

	session, err := s.sessions.FindByID(ctx, refreshRecord.SessionID)
	if err != nil {
		if dErrors.Is(err, dErrors.CodeNotFound) {
			s.authFailure(ctx, "session_not_found_for_refresh_token", false,
				"client_id", req.ClientID,
				"session_id", refreshRecord.SessionID.String(),
			)
			return nil, dErrors.New(dErrors.CodeUnauthorized, "invalid refresh token")
		}
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to find session")
	}

	if session.Status == StatusRevoked {
		s.authFailure(ctx, "session_revoked", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"client_id", session.ClientID,
		)
		return nil, dErrors.New(dErrors.CodeUnauthorized, "session has been revoked")
	}

	if req.ClientID != session.ClientID {
		s.authFailure(ctx, "client_id_mismatch", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"expected_client_id", session.ClientID,
			"provided_client_id", req.ClientID,
		)
		return nil, dErrors.New(dErrors.CodeUnauthorized, "client_id mismatch")
	}

	if time.Now().After(session.ExpiresAt) {
		s.authFailure(ctx, "session_expired", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"client_id", session.ClientID,
		)
		return nil, dErrors.New(dErrors.CodeUnauthorized, "session expired")
	}

	mutableSession := *session
	s.applyDeviceBinding(ctx, &mutableSession)
	// Used for session management UI / risk signals.
	mutableSession.LastSeenAt = time.Now()

	artifacts, err := s.generateTokenArtifacts(&mutableSession)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	mutableSession.LastRefreshedAt = &now
	writeErr := s.tx.RunInTx(ctx, func(stores TxAuthStores) error {
		if err := stores.Sessions.UpdateSession(ctx, &mutableSession); err != nil {
			return err
		}
		if err := stores.RefreshTokens.Consume(ctx, req.RefreshToken, now); err != nil {
			return err
		}
		if err := stores.RefreshTokens.Create(ctx, artifacts.refreshRecord); err != nil {
			return err
		}
		return nil
	})
	if writeErr != nil {
		return nil, dErrors.Wrap(writeErr, dErrors.CodeInternal, "failed to persist token refresh")
	}

	s.logAudit(ctx,
		string(audit.EventTokenRefreshed),
		"session_id", mutableSession.ID.String(),
		"user_id", mutableSession.UserID.String(),
		"client_id", mutableSession.ClientID,
	)
	s.incrementTokenRequests()

	return &models.TokenResult{
		AccessToken:  artifacts.accessToken,
		IDToken:      artifacts.idToken,
		RefreshToken: artifacts.refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    s.TokenTTL,
	}, nil
}
