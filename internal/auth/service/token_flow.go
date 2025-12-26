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
	stores txAuthStores,
	params tokenFlowTxParams,
) (*tokenFlowTxResult, error) {
	// Build device state from current session + context signals
	deviceState := *params.Session
	s.applyDeviceBinding(ctx, &deviceState)

	// Determine if session should be activated (code exchange only)
	activate := params.ActivateOnFirstUse && params.Session.IsPendingConsent()

	// Advance session state based on flow type
	var session *models.Session
	var err error
	clientID := params.TokenContext.Client.ID.String()
	artifacts := params.Artifacts

	if params.ActivateOnFirstUse {
		session, err = stores.Sessions.AdvanceLastSeen(
			ctx,
			params.Session.ID,
			clientID,
			params.Now,
			artifacts.accessTokenJTI,
			activate,
			deviceState.DeviceID,
			deviceState.DeviceFingerprintHash,
		)
	} else {
		session, err = stores.Sessions.AdvanceLastRefreshed(
			ctx,
			params.Session.ID,
			clientID,
			params.Now,
			artifacts.accessTokenJTI,
			deviceState.DeviceID,
			deviceState.DeviceFingerprintHash,
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
