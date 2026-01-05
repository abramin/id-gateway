package service

import (
	"context"
	"fmt"
	"time"

	"credo/internal/auth/models"
	"credo/pkg/platform/audit"
	"credo/pkg/requestcontext"
)

// exchangeAuthorizationCode handles the token exchange flow for authorization codes.
// It validates the authorization code, ensures the session and client are consistent,
// consumes the code to prevent reuse, and issues new tokens.
func (s *Service) exchangeAuthorizationCode(ctx context.Context, req *models.TokenRequest) (*models.TokenResult, error) {
	start := time.Now()
	var tenantID, clientID string // for PRD-020 tenant-labeled metrics
	defer func() {
		durationMs := float64(time.Since(start).Milliseconds())
		s.observeTokenExchangeDuration(durationMs)
		if tenantID != "" && clientID != "" {
			s.observeTokenExchangeDurationByTenant(tenantID, clientID, durationMs)
		}
	}()

	now := requestcontext.Now(ctx)
	var (
		codeRecord *models.AuthorizationCodeRecord
		session    *models.Session
	)
	code, err := s.codes.FindByCode(ctx, req.Code)
	if err != nil {
		return nil, s.handleTokenError(ctx, err, req.ClientID, nil, TokenFlowCode)
	}
	sessionID := code.SessionID.String()
	session, err = s.sessions.FindByID(ctx, code.SessionID)
	if err != nil {
		return nil, s.handleTokenError(ctx, err, req.ClientID, &sessionID, TokenFlowCode)
	}

	tc, artifacts, err := s.prepareTokenFlow(ctx, session, req.ClientID, &sessionID, TokenFlowCode)
	if err != nil {
		return nil, err
	}
	// PRD-020: Capture tenant/client for labeled metrics (used in defer)
	tenantID = tc.Tenant.ID.String()
	clientID = tc.Client.ID.String()

	txErr := s.tx.RunInTx(ctx, func(stores txAuthStores) error {
		var err error
		codeRecord, err = s.consumeCodeWithReplayProtection(ctx, stores, req.Code, req.RedirectURI, now)
		if err != nil {
			return err
		}

		// Set tenant ID on the pre-fetched session for executeTokenFlowTx.
		// The session is re-read inside executeTokenFlowTx via the Execute pattern,
		// which provides atomic validation and mutation.
		session.TenantID = tc.Tenant.ID

		result, err := s.executeTokenFlowTx(ctx, stores, tokenFlowTxParams{
			Session:            session,
			TokenContext:       tc,
			Now:                now,
			ActivateOnFirstUse: true,
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
		if codeRecord != nil {
			id := codeRecord.SessionID.String()
			recordID = &id
		}
		return nil, s.handleTokenError(ctx, txErr, req.ClientID, recordID, TokenFlowCode)
	}

	s.logAudit(ctx,
		string(audit.EventTokenIssued),
		"session_id", session.ID.String(),
		"user_id", session.UserID.String(),
		"client_id", session.ClientID,
	)
	s.incrementTokenRequests()

	return s.buildTokenResult(artifacts, session.RequestedScope), nil
}

// consumeCodeWithReplayProtection consumes an authorization code and handles replay attacks.
// If the code was already used, it revokes the associated session to mitigate token theft.
func (s *Service) consumeCodeWithReplayProtection(
	ctx context.Context,
	stores txAuthStores,
	code, redirectURI string,
	now time.Time,
) (*models.AuthorizationCodeRecord, error) {
	// Use Execute pattern: domain errors pass through unchanged
	codeRecord, err := stores.Codes.Execute(ctx, code,
		func(rec *models.AuthorizationCodeRecord) error {
			return rec.ValidateForConsume(redirectURI, now)
		},
		func(rec *models.AuthorizationCodeRecord) {
			rec.MarkUsed()
		},
	)
	if err != nil {
		if codeRecord != nil {
			if revokeErr := revokeSessionOnReplay(ctx, stores, err, codeRecord.SessionID, now); revokeErr != nil {
				return nil, revokeErr
			}
		}
		return nil, fmt.Errorf("consume authorization code: %w", err)
	}
	return codeRecord, nil
}
