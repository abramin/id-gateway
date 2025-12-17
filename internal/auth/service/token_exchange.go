package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"credo/internal/audit"
	"credo/internal/auth/models"
	authCodeStore "credo/internal/auth/store/authorization-code"
	dErrors "credo/pkg/domain-errors"
)

func (s *Service) exchangeAuthorizationCode(ctx context.Context, req *models.TokenRequest) (*models.TokenResult, error) {
	now := time.Now()
	var (
		codeRecord *models.AuthorizationCodeRecord
		session    *models.Session
		artifacts  *tokenArtifacts
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
	tc, err := s.resolveTokenContext(ctx, session, req.ClientID)
	if err != nil {
		return nil, s.handleTokenError(ctx, err, req.ClientID, &sessionID, TokenFlowCode)
	}

	if models.UserStatus(tc.Client.Status) != models.UserStatusActive {
		return nil, dErrors.New(dErrors.CodeForbidden, "client is not active")
	}
	txErr := s.tx.RunInTx(ctx, func(stores TxAuthStores) error {
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

		session, err = stores.Sessions.FindByID(ctx, codeRecord.SessionID)
		if err != nil {
			return fmt.Errorf("fetch session: %w", err)
		}

		mutableSession := *session
		s.applyDeviceBinding(ctx, &mutableSession)
		mutableSession.LastSeenAt = now
		mutableSession.TenantID = tc.Tenant.ID
		activate := false
		if mutableSession.Status == string(models.SessionStatusPendingConsent) {
			mutableSession.Status = string(models.SessionStatusActive)
			activate = true
		}

		artifacts, err = s.generateTokenArtifacts(&mutableSession)
		if err != nil {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to generate tokens")
		}

		session, err = stores.Sessions.AdvanceLastSeen(ctx, session.ID, tc.Client.ID.String(), now, artifacts.accessTokenJTI, activate, mutableSession.DeviceID, mutableSession.DeviceFingerprintHash)
		if err != nil {
			return fmt.Errorf("advance last seen: %w", err)
		}

		if err := stores.RefreshTokens.Create(ctx, artifacts.refreshRecord); err != nil {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to create refresh token")
		}
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
		ExpiresIn:    s.TokenTTL, // Access token TTL
	}, nil
}
