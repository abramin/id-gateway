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

	if !tc.Client.IsActive() {
		return nil, dErrors.New(dErrors.CodeForbidden, "client is not active")
	}

	// Generate tokens BEFORE entering transaction to avoid holding mutex during JWT generation
	artifacts, err := s.generateTokenArtifacts(session)
	if err != nil {
		return nil, s.handleTokenError(ctx, dErrors.Wrap(err, dErrors.CodeInternal, "failed to generate tokens"), req.ClientID, &sessionID, TokenFlowRefresh)
	}

	// Perform transactional updates with session-based sharding
	txCtx := context.WithValue(ctx, txSessionKeyCtx, sessionID)
	txErr := s.tx.RunInTx(txCtx, func(stores TxAuthStores) error {
		// Step 1: Consume refresh token (prevents replay attacks)
		var err error
		refreshRecord, err = stores.RefreshTokens.ConsumeRefreshToken(ctx, req.RefreshToken, now)
		if err != nil {
			return fmt.Errorf("consume refresh token: %w", err)
		}

		// Step 2: Load session for token generation
		session, err = stores.Sessions.FindByID(ctx, refreshRecord.SessionID)
		if err != nil {
			return fmt.Errorf("fetch session: %w", err)
		}

		// Step 3: Update session and persist refresh token (artifacts pre-generated)
		result, err := s.executeTokenFlowTx(ctx, stores, tokenFlowTxParams{
			Session:            session,
			TokenContext:       tc,
			Now:                now,
			ActivateOnFirstUse: false,
			Artifacts:          artifacts,
		})
		if err != nil {
			return err
		}
		session = result.Session
		return nil
	})
	if txErr != nil {
		var recordID *string
		if refreshRecord != nil {
			id := refreshRecord.SessionID.String()
			recordID = &id
		}
		return nil, s.handleTokenError(ctx, txErr, req.ClientID, recordID, TokenFlowRefresh)
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

