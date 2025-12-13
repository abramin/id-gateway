package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"credo/internal/audit"
	"credo/internal/auth/models"
	refreshTokenStore "credo/internal/auth/store/refresh-token"
	sessionStore "credo/internal/auth/store/session"
	dErrors "credo/pkg/domain-errors"
)

func (s *Service) refreshWithRefreshToken(ctx context.Context, req *models.TokenRequest) (*models.TokenResult, error) {
	now := time.Now()
	var (
		refreshRecord *models.RefreshTokenRecord
		session       *models.Session
		artifacts     *tokenArtifacts
	)

	txErr := s.tx.RunInTx(ctx, func(stores TxAuthStores) error {
		var err error
		refreshRecord, err = stores.RefreshTokens.ConsumeRefreshToken(ctx, req.RefreshToken, now)
		if err != nil {
			return err
		}

		session, err = stores.Sessions.FindByID(ctx, refreshRecord.SessionID)
		if err != nil {
			return err
		}

		mutableSession := *session
		s.applyDeviceBinding(ctx, &mutableSession)
		mutableSession.LastSeenAt = now
		mutableSession.LastRefreshedAt = &now

		artifacts, err = s.generateTokenArtifacts(&mutableSession)
		if err != nil {
			return err
		}

		session, err = stores.Sessions.AdvanceLastRefreshed(ctx, session.ID, req.ClientID, now, artifacts.accessTokenJTI, mutableSession.DeviceID, mutableSession.DeviceFingerprintHash)
		if err != nil {
			return err
		}
		if err := stores.RefreshTokens.Create(ctx, artifacts.refreshRecord); err != nil {
			return err
		}
		return nil
	})
	if txErr != nil {
		return nil, s.handleRefreshTokenError(ctx, txErr, req, refreshRecord)
	}

	s.logAudit(ctx,
		string(audit.EventTokenRefreshed),
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
		ExpiresIn:    s.TokenTTL,
	}, nil
}

func (s *Service) handleRefreshTokenError(ctx context.Context, err error, req *models.TokenRequest, refreshRecord *models.RefreshTokenRecord) error {
	switch {
	case errors.Is(err, refreshTokenStore.ErrNotFound):
		s.authFailure(ctx, "refresh_token_not_found", false, "client_id", req.ClientID)
		return dErrors.New(dErrors.CodeUnauthorized, "invalid refresh token")
	case errors.Is(err, refreshTokenStore.ErrRefreshTokenUsed):
		attrs := []any{"client_id", req.ClientID}
		if refreshRecord != nil {
			attrs = append(attrs, "session_id", refreshRecord.SessionID.String())
		}
		s.authFailure(ctx, "refresh_token_reused", false, attrs...)
		return dErrors.New(dErrors.CodeUnauthorized, "invalid refresh token")
	case errors.Is(err, refreshTokenStore.ErrRefreshTokenExpired):
		attrs := []any{"client_id", req.ClientID}
		if refreshRecord != nil {
			attrs = append(attrs, "session_id", refreshRecord.SessionID.String())
		}
		s.authFailure(ctx, "refresh_token_expired", false, attrs...)
		return dErrors.New(dErrors.CodeUnauthorized, "refresh token expired")
	case errors.Is(err, sessionStore.ErrNotFound):
		attrs := []any{"client_id", req.ClientID}
		if refreshRecord != nil {
			attrs = append(attrs, "session_id", refreshRecord.SessionID.String())
		}
		s.authFailure(ctx, "session_not_found_for_refresh_token", false, attrs...)
		return dErrors.New(dErrors.CodeUnauthorized, "invalid refresh token")
	case errors.Is(err, sessionStore.ErrSessionRevoked):
		attrs := []any{"client_id", req.ClientID}
		if refreshRecord != nil {
			attrs = append(attrs, "session_id", refreshRecord.SessionID.String())
		}
		s.authFailure(ctx, "session_revoked", false, attrs...)
		return dErrors.New(dErrors.CodeUnauthorized, "session has been revoked")
	case dErrors.Is(err, dErrors.CodeUnauthorized):
		reason := "session_invalid"
		switch {
		case strings.Contains(err.Error(), "client_id"):
			reason = "client_id_mismatch"
		case strings.Contains(err.Error(), "expired"):
			reason = "session_expired"
		case strings.Contains(err.Error(), "invalid state"):
			reason = "invalid_session_status"
		}
		attrs := []any{"client_id", req.ClientID}
		if refreshRecord != nil {
			attrs = append(attrs, "session_id", refreshRecord.SessionID.String())
		}
		s.authFailure(ctx, reason, false, attrs...)
		return dErrors.New(dErrors.CodeUnauthorized, err.Error())
	default:
		if dErrors.Is(err, dErrors.CodeInternal) {
			return err
		}
		return dErrors.Wrap(err, dErrors.CodeInternal, "failed to persist token refresh")
	}
}
