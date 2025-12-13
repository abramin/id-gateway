package service

import (
	"context"
	"errors"
	"time"

	"credo/internal/audit"
	"credo/internal/auth/models"
	sessionStore "credo/internal/auth/store/session"
	dErrors "credo/pkg/domain-errors"
)

func (s *Service) exchangeAuthorizationCode(ctx context.Context, req *models.TokenRequest) (*models.TokenResult, error) {
	codeRecord, err := s.findAuthorizationCode(ctx, req)
	if err != nil {
		return nil, err
	}
	if err := s.validateAuthorizationCode(ctx, req, codeRecord); err != nil {
		return nil, err
	}

	session, err := s.findSessionForCode(ctx, req, codeRecord)
	if err != nil {
		return nil, err
	}
	if err := s.validateSessionForTokenExchange(ctx, req, session); err != nil {
		return nil, err
	}

	mutableSession := *session
	s.applyDeviceBinding(ctx, &mutableSession)
	// Used for session management UI / risk signals.
	mutableSession.LastSeenAt = time.Now()

	// Transition from pending_consent to active on first successful exchange.
	if mutableSession.Status == StatusPendingConsent {
		mutableSession.Status = StatusActive
	}

	artifacts, err := s.generateTokenArtifacts(&mutableSession)
	if err != nil {
		return nil, err
	}
	if err := s.persistTokenExchange(ctx, &mutableSession, codeRecord, artifacts.refreshRecord); err != nil {
		return nil, err
	}

	s.logAudit(ctx,
		string(audit.EventTokenIssued),
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
		ExpiresIn:    s.TokenTTL, // Access token TTL
	}, nil
}

func (s *Service) findAuthorizationCode(ctx context.Context, req *models.TokenRequest) (*models.AuthorizationCodeRecord, error) {
	codeRecord, err := s.codes.FindByCode(ctx, req.Code)
	if err != nil {
		if errors.Is(err, sessionStore.ErrNotFound) {
			s.authFailure(ctx, "code_not_found", false,
				"client_id", req.ClientID,
			)
			return nil, dErrors.New(dErrors.CodeUnauthorized, "invalid authorization code")
		}
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to find code")
	}
	return codeRecord, nil
}

func (s *Service) validateAuthorizationCode(ctx context.Context, req *models.TokenRequest, codeRecord *models.AuthorizationCodeRecord) error {
	if time.Now().After(codeRecord.ExpiresAt) {
		s.authFailure(ctx, "authorization_code_expired", false,
			"client_id", req.ClientID,
			"code", req.Code,
		)
		return dErrors.New(dErrors.CodeUnauthorized, "authorization code expired")
	}

	if codeRecord.Used {
		// Security: Code reuse indicates replay attack - revoke the session.
		if err := s.sessions.RevokeSession(ctx, codeRecord.SessionID); err != nil {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to revoke compromised session")
		}
		s.authFailure(ctx, "authorization_code_reused", false,
			"client_id", req.ClientID,
			"session_id", codeRecord.SessionID.String(),
		)
		return dErrors.New(dErrors.CodeUnauthorized, "authorization code already used")
	}

	if codeRecord.RedirectURI != req.RedirectURI {
		s.authFailure(ctx, "redirect_uri_mismatch", false,
			"client_id", req.ClientID,
		)
		return dErrors.New(dErrors.CodeBadRequest, "redirect_uri mismatch")
	}

	return nil
}

func (s *Service) findSessionForCode(ctx context.Context, req *models.TokenRequest, codeRecord *models.AuthorizationCodeRecord) (*models.Session, error) {
	session, err := s.sessions.FindByID(ctx, codeRecord.SessionID)
	if err != nil {
		if errors.Is(err, sessionStore.ErrNotFound) {
			s.authFailure(ctx, "session_not_found", false,
				"client_id", req.ClientID,
			)
			return nil, dErrors.New(dErrors.CodeUnauthorized, "invalid authorization code")
		}
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to find session")
	}
	return session, nil
}

func (s *Service) validateSessionForTokenExchange(ctx context.Context, req *models.TokenRequest, session *models.Session) error {
	if req.ClientID != session.ClientID {
		s.authFailure(ctx, "client_id_mismatch", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"expected_client_id", session.ClientID,
			"provided_client_id", req.ClientID,
		)
		return dErrors.New(dErrors.CodeBadRequest, "client_id mismatch")
	}

	if session.Status == "revoked" {
		s.authFailure(ctx, "session_revoked", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"client_id", session.ClientID,
		)
		return dErrors.New(dErrors.CodeUnauthorized, "session has been revoked")
	}

	// Accept both pending_consent and active (for idempotency if code is exchanged twice).
	if session.Status != StatusPendingConsent && session.Status != StatusActive {
		s.authFailure(ctx, "invalid_session_status", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"client_id", session.ClientID,
			"status", session.Status,
		)
		return dErrors.New(dErrors.CodeUnauthorized, "session in invalid state")
	}

	if time.Now().After(session.ExpiresAt) {
		s.authFailure(ctx, "session_expired", false,
			"session_id", session.ID.String(),
			"user_id", session.UserID.String(),
			"client_id", session.ClientID,
		)
		return dErrors.New(dErrors.CodeUnauthorized, "session expired")
	}

	return nil
}

func (s *Service) persistTokenExchange(
	ctx context.Context,
	session *models.Session,
	codeRecord *models.AuthorizationCodeRecord,
	refreshRecord *models.RefreshTokenRecord,
) error {
	writeErr := s.tx.RunInTx(ctx, func(stores TxAuthStores) error {
		if err := stores.Sessions.UpdateSession(ctx, session); err != nil {
			return err
		}
		if err := stores.RefreshTokens.Create(ctx, refreshRecord); err != nil {
			return err
		}
		if err := stores.Codes.MarkUsed(ctx, codeRecord.Code); err != nil {
			return err
		}
		return nil
	})
	if writeErr != nil {
		return dErrors.Wrap(writeErr, dErrors.CodeInternal, "failed to persist token exchange")
	}
	return nil
}
