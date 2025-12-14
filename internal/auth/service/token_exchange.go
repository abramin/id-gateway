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
		return nil, s.handleTokenError(ctx, err, req.ClientID, "", "code")
	}
	session, err = s.sessions.FindByID(ctx, code.SessionID)
	if err != nil {
		return nil, s.handleTokenError(ctx, err, req.ClientID, code.SessionID.String(), "code")
	}
	tc, err := s.resolveTokenContext(ctx, session)
	if err != nil {
		return nil, s.handleTokenError(ctx, err, req.ClientID, code.SessionID.String(), "code")
	}

	if models.UserStatus(tc.Client.Status) != models.UserStatusActive {
		return nil, dErrors.New(dErrors.CodeForbidden, "client is not active")
	}
	txErr := s.tx.RunInTx(ctx, func(stores TxAuthStores) error {
		var err error
		codeRecord, err = stores.Codes.ConsumeAuthCode(ctx, req.Code, req.RedirectURI, now)
		if err != nil {
			if errors.Is(err, authCodeStore.ErrAuthCodeUsed) && codeRecord != nil {
				err = stores.Sessions.RevokeSessionIfActive(ctx, codeRecord.SessionID, now)
				if err != nil {
					return dErrors.Wrap(err, dErrors.CodeInternal, "failed to revoke session for used code")
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
		recordID := ""
		if codeRecord != nil {
			recordID = codeRecord.SessionID.String()
		}
		return nil, s.handleTokenError(ctx, txErr, req.ClientID, recordID, "code")
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
