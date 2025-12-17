package service

import (
	"context"
	"fmt"
	"time"

	"credo/internal/audit"
	"credo/internal/auth/models"
	dErrors "credo/pkg/domain-errors"
)

func (s *Service) refreshWithRefreshToken(ctx context.Context, req *models.TokenRequest) (*models.TokenResult, error) {
	now := time.Now()
	var (
		refreshRecord *models.RefreshTokenRecord
		session       *models.Session
		artifacts     *tokenArtifacts
	)

	// Find refresh token and session (non-transactional reads for validation)
	refreshRecord, err := s.refreshTokens.Find(ctx, req.RefreshToken)
	if err != nil {
		return nil, s.handleTokenError(ctx, err, req.ClientID, nil, TokenFlowRefresh)
	}

	sessionID := refreshRecord.SessionID.String()
	session, err = s.sessions.FindByID(ctx, refreshRecord.SessionID)
	if err != nil {
		return nil, s.handleTokenError(ctx, err, req.ClientID, &sessionID, TokenFlowRefresh)
	}

	// Validate client and user status before issuing new tokens (PRD-026A FR-4.5.4)
	tc, err := s.resolveTokenContext(ctx, session, req.ClientID)
	if err != nil {
		return nil, s.handleTokenError(ctx, err, req.ClientID, &sessionID, TokenFlowRefresh)
	}

	if models.UserStatus(tc.Client.Status) != models.UserStatusActive {
		return nil, dErrors.New(dErrors.CodeForbidden, "client is not active")
	}

	// Now perform transactional updates
	txErr := s.tx.RunInTx(ctx, func(stores TxAuthStores) error {
		var err error
		// Consume the refresh token (transactional to prevent replay)
		refreshRecord, err = stores.RefreshTokens.ConsumeRefreshToken(ctx, req.RefreshToken, now)
		if err != nil {
			return fmt.Errorf("consume refresh token: %w", err)
		}

		session, err = stores.Sessions.FindByID(ctx, refreshRecord.SessionID)
		if err != nil {
			return fmt.Errorf("fetch session: %w", err)
		}

		mutableSession := *session
		s.applyDeviceBinding(ctx, &mutableSession)
		mutableSession.LastSeenAt = now
		mutableSession.LastRefreshedAt = &now

		artifacts, err = s.generateTokenArtifacts(&mutableSession)
		if err != nil {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to generate tokens")
		}

		session, err = stores.Sessions.AdvanceLastRefreshed(ctx, session.ID, tc.Client.ID.String(), now, artifacts.accessTokenJTI, mutableSession.DeviceID, mutableSession.DeviceFingerprintHash)
		if err != nil {
			return fmt.Errorf("advance session last refreshed: %w", err)
		}
		if err := stores.RefreshTokens.Create(ctx, artifacts.refreshRecord); err != nil {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to create refresh token")
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
	var recordID *string
	if refreshRecord != nil {
		id := refreshRecord.SessionID.String()
		recordID = &id
	}
	return s.handleTokenError(ctx, err, req.ClientID, recordID, TokenFlowRefresh)
}
