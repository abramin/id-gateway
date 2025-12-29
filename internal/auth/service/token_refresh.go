package service

import (
	"context"
	"fmt"
	"time"

	"credo/internal/auth/models"
	"credo/pkg/platform/audit"
	"credo/pkg/platform/middleware/requesttime"
)

func (s *Service) refreshWithRefreshToken(ctx context.Context, req *models.TokenRequest) (*models.TokenResult, error) {
	start := time.Now()
	defer func() {
		s.observeTokenRefreshDuration(float64(time.Since(start).Milliseconds()))
	}()

	now := requesttime.Now(ctx)
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
	tc, artifacts, err := s.prepareTokenFlow(ctx, session, req.ClientID, &sessionID, TokenFlowRefresh)
	if err != nil {
		return nil, err
	}

	// Perform transactional updates with session-based sharding
	txCtx := context.WithValue(ctx, txSessionKeyCtx, sessionID)
	txErr := s.tx.RunInTx(txCtx, func(stores txAuthStores) error {
		// Step 1: Consume refresh token with replay protection
		var err error
		refreshRecord, err = s.consumeRefreshTokenWithReplayProtection(ctx, stores, req.RefreshToken, now)
		if err != nil {
			return err
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

	return s.buildTokenResult(artifacts, session.RequestedScope), nil
}

// consumeRefreshTokenWithReplayProtection consumes a refresh token and handles replay attacks.
// If the token was already used, it revokes the associated session to mitigate token theft.
func (s *Service) consumeRefreshTokenWithReplayProtection(
	ctx context.Context,
	stores txAuthStores,
	token string,
	now time.Time,
) (*models.RefreshTokenRecord, error) {
	// Use Execute pattern: domain errors pass through unchanged
	refreshRecord, err := stores.RefreshTokens.Execute(ctx, token,
		func(rec *models.RefreshTokenRecord) error {
			return rec.ValidateForConsume(now)
		},
		func(rec *models.RefreshTokenRecord) {
			rec.MarkUsed(now)
		},
	)
	if err != nil {
		if refreshRecord != nil {
			if revokeErr := revokeSessionOnReplay(ctx, stores, err, refreshRecord.SessionID, now); revokeErr != nil {
				return nil, revokeErr
			}
		}
		return nil, fmt.Errorf("consume refresh token: %w", err)
	}
	return refreshRecord, nil
}
