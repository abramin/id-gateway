package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"credo/internal/auth/models"
	authCodeStore "credo/internal/auth/store/authorization-code"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	"credo/pkg/platform/middleware/requesttime"
)

// exchangeAuthorizationCode handles the token exchange flow for authorization codes.
// It validates the authorization code, ensures the session and client are consistent,
// consumes the code to prevent reuse, and issues new tokens.
func (s *Service) exchangeAuthorizationCode(ctx context.Context, req *models.TokenRequest) (*models.TokenResult, error) {
	now := requesttime.Now(ctx)
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

	// Add session ID to context for sharded locking
	txCtx := context.WithValue(ctx, txSessionKeyCtx, sessionID)
	txErr := s.tx.RunInTx(txCtx, func(stores txAuthStores) error {
		// Step 1: Consume authorization code (with replay attack protection)
		var err error
		codeRecord, err = stores.Codes.ConsumeAuthCode(ctx, req.Code, req.RedirectURI, now)
		if err != nil {
			if errors.Is(err, authCodeStore.ErrAuthCodeUsed) && codeRecord != nil {
				revokeErr := stores.Sessions.RevokeSessionIfActive(ctx, codeRecord.SessionID, now)
				if revokeErr != nil {
					return dErrors.Wrap(revokeErr, dErrors.CodeInternal, "failed to revoke session for used code")
				}
			}
			return fmt.Errorf("consume authorization code: %w", err)
		}

		// Step 2: Load session for token generation
		session, err = stores.Sessions.FindByID(ctx, codeRecord.SessionID)
		if err != nil {
			return fmt.Errorf("fetch session: %w", err)
		}
		session.TenantID = tc.Tenant.ID

		// Step 3: Update session and persist refresh token (artifacts pre-generated)
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

	return &models.TokenResult{
		AccessToken:  artifacts.accessToken,
		IDToken:      artifacts.idToken,
		RefreshToken: artifacts.refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.TokenTTL.Seconds()), // Access token TTL in seconds
		Scope:        strings.Join(session.RequestedScope, " "),
	}, nil
}
