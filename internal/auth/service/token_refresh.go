package service

import (
	"context"
	"time"

	"credo/internal/audit"
	"credo/internal/auth/models"
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
	recordID := ""
	if refreshRecord != nil {
		recordID = refreshRecord.SessionID.String()
	}
	return s.handleTokenError(ctx, err, req.ClientID, recordID, "refresh")
}
