package service

import (
	"context"
	"time"

	"credo/internal/auth/models"
	dErrors "credo/pkg/domain-errors"
)

// tokenFlowTxParams captures the inputs for token transaction execution.
// Both authorization code exchange and refresh token flows use this structure.
type tokenFlowTxParams struct {
	Session      *models.Session
	TokenContext *tokenContext
	Now          time.Time
	// ActivateOnFirstUse is true for code exchange (activates pending sessions),
	// false for refresh (updates LastRefreshedAt instead).
	ActivateOnFirstUse bool
	// Artifacts are pre-generated BEFORE entering the transaction to avoid
	// holding the mutex during CPU-intensive JWT generation.
	Artifacts *tokenArtifacts
}

// tokenFlowTxResult holds the outputs from a successful token transaction.
type tokenFlowTxResult struct {
	Session *models.Session
}

// executeTokenFlowTx runs the common transactional portion of token issuance.
// It handles device binding, session advancement, and refresh token creation.
// IMPORTANT: Token artifacts must be pre-generated BEFORE calling this function
// to avoid holding the transaction lock during CPU-intensive JWT generation.
func (s *Service) executeTokenFlowTx(
	ctx context.Context,
	stores TxAuthStores,
	params tokenFlowTxParams,
) (*tokenFlowTxResult, error) {
	mutableSession := *params.Session
	s.applyDeviceBinding(ctx, &mutableSession)
	mutableSession.LastSeenAt = params.Now

	activate := false
	if params.ActivateOnFirstUse {
		// Code exchange: activate session if pending consent
		if mutableSession.IsPendingConsent() {
			mutableSession.Activate()
			activate = true
		}
	}

	// Use pre-generated artifacts (generated outside transaction lock)
	artifacts := params.Artifacts

	// Advance session state based on flow type
	var session *models.Session
	var err error
	clientID := params.TokenContext.Client.ID.String()

	if params.ActivateOnFirstUse {
		session, err = stores.Sessions.AdvanceLastSeen(
			ctx,
			params.Session.ID,
			clientID,
			params.Now,
			artifacts.accessTokenJTI,
			activate,
			mutableSession.DeviceID,
			mutableSession.DeviceFingerprintHash,
		)
	} else {
		session, err = stores.Sessions.AdvanceLastRefreshed(
			ctx,
			params.Session.ID,
			clientID,
			params.Now,
			artifacts.accessTokenJTI,
			mutableSession.DeviceID,
			mutableSession.DeviceFingerprintHash,
		)
	}
	if err != nil {
		return nil, err
	}

	if err := stores.RefreshTokens.Create(ctx, artifacts.refreshRecord); err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to create refresh token")
	}

	return &tokenFlowTxResult{
		Session: session,
	}, nil
}
