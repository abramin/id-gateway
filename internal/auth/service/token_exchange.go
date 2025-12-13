package service

import (
	"context"
	"errors"
	"time"

	"credo/internal/audit"
	"credo/internal/auth/models"
	authCodeStore "credo/internal/auth/store/authorization-code"
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
	recordID := ""
	if codeRecord != nil {
		recordID = codeRecord.SessionID.String()
	}
	return s.handleTokenError(ctx, err, req.ClientID, recordID, "code")
}
