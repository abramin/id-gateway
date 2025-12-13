package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"credo/internal/audit"
	"credo/internal/auth/models"
	authCodeStore "credo/internal/auth/store/authorization-code"
	sessionStore "credo/internal/auth/store/session"
	dErrors "credo/pkg/domain-errors"
)

func (s *Service) exchangeAuthorizationCode(ctx context.Context, req *models.TokenRequest) (*models.TokenResult, error) {
	now := time.Now()
	var (
		codeRecord *models.AuthorizationCodeRecord
		session    *models.Session
		artifacts  *tokenArtifacts
	)

	txErr := s.tx.RunInTx(ctx, func(stores TxAuthStores) error {
		var err error
		codeRecord, err = stores.Codes.ConsumeAuthCode(ctx, req.Code, req.RedirectURI, now)
		if err != nil {
			if errors.Is(err, authCodeStore.ErrAuthCodeUsed) && codeRecord != nil {
				_ = stores.Sessions.RevokeSessionIfActive(ctx, codeRecord.SessionID, now)
			}
			return err
		}

		session, err = stores.Sessions.FindByID(ctx, codeRecord.SessionID)
		if err != nil {
			return err
		}

		mutableSession := *session
		s.applyDeviceBinding(ctx, &mutableSession)
		mutableSession.LastSeenAt = now
		activate := false
		if mutableSession.Status == StatusPendingConsent {
			mutableSession.Status = StatusActive
			activate = true
		}

		artifacts, err = s.generateTokenArtifacts(&mutableSession)
		if err != nil {
			return err
		}

		session, err = stores.Sessions.AdvanceLastSeen(ctx, session.ID, req.ClientID, now, artifacts.accessTokenJTI, activate, mutableSession.DeviceID, mutableSession.DeviceFingerprintHash)
		if err != nil {
			return err
		}

		if err := stores.RefreshTokens.Create(ctx, artifacts.refreshRecord); err != nil {
			return err
		}
		return nil
	})
	if txErr != nil {
		return nil, s.handleAuthorizationCodeError(ctx, txErr, req, codeRecord)
	}

	s.logAudit(ctx,
		string(audit.EventTokenIssued),
		"session_id", session.ID.String(),
		"user_id", session.UserID.String(),
		"client_id", session.ClientID,
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

func (s *Service) handleAuthorizationCodeError(ctx context.Context, err error, req *models.TokenRequest, codeRecord *models.AuthorizationCodeRecord) error {
	switch {
	case errors.Is(err, authCodeStore.ErrNotFound):
		s.authFailure(ctx, "code_not_found", false, "client_id", req.ClientID)
		return dErrors.New(dErrors.CodeUnauthorized, "invalid authorization code")
	case errors.Is(err, authCodeStore.ErrAuthCodeExpired):
		s.authFailure(ctx, "authorization_code_expired", false, "client_id", req.ClientID, "code", req.Code)
		return dErrors.New(dErrors.CodeUnauthorized, "authorization code expired")
	case errors.Is(err, authCodeStore.ErrAuthCodeUsed):
		attrs := []any{"client_id", req.ClientID}
		if codeRecord != nil {
			attrs = append(attrs, "session_id", codeRecord.SessionID.String())
		}
		s.authFailure(ctx, "authorization_code_reused", false, attrs...)
		return dErrors.New(dErrors.CodeUnauthorized, "authorization code already used")
	case dErrors.Is(err, dErrors.CodeBadRequest):
		s.authFailure(ctx, "redirect_uri_mismatch", false, "client_id", req.ClientID)
		return dErrors.New(dErrors.CodeBadRequest, "redirect_uri mismatch")
	case errors.Is(err, sessionStore.ErrNotFound):
		s.authFailure(ctx, "session_not_found", false, "client_id", req.ClientID)
		return dErrors.New(dErrors.CodeUnauthorized, "invalid authorization code")
	case errors.Is(err, sessionStore.ErrSessionRevoked):
		attrs := []any{"client_id", req.ClientID}
		if codeRecord != nil {
			attrs = append(attrs, "session_id", codeRecord.SessionID.String())
		}
		s.authFailure(ctx, "session_revoked", false, attrs...)
		return dErrors.New(dErrors.CodeUnauthorized, "session has been revoked")
	case dErrors.Is(err, dErrors.CodeUnauthorized):
		reason := "invalid_session_state"
		switch {
		case strings.Contains(err.Error(), "client_id"):
			reason = "client_id_mismatch"
		case strings.Contains(err.Error(), "expired"):
			reason = "session_expired"
		case strings.Contains(err.Error(), "invalid state"):
			reason = "invalid_session_status"
		}
		attrs := []any{"client_id", req.ClientID}
		if codeRecord != nil {
			attrs = append(attrs, "session_id", codeRecord.SessionID.String())
		}
		s.authFailure(ctx, reason, false, attrs...)
		return dErrors.New(dErrors.CodeUnauthorized, err.Error())
	default:
		if dErrors.Is(err, dErrors.CodeInternal) {
			return err
		}
		return dErrors.Wrap(err, dErrors.CodeInternal, "failed to persist token exchange")
	}
}
