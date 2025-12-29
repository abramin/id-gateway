package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"credo/internal/auth/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/sentinel"
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

	clientID := params.TokenContext.Client.ID
	artifacts := params.Artifacts

	// Execute atomic session validation and mutation
	// Domain errors from ValidateForAdvance pass through unchanged (no sentinel translation)
	session, err := stores.Sessions.Execute(ctx, params.Session.ID,
		// Validation callback - returns domain errors
		func(sess *models.Session) error {
			// allowPending=true for code exchange (allows pending_consent status)
			// allowPending=false for refresh (requires active status)
			return sess.ValidateForAdvance(clientID, params.Now, params.ActivateOnFirstUse)
		},
		// Mutation callback - applies state changes
		func(sess *models.Session) {
			if params.ActivateOnFirstUse {
				sess.RecordActivity(params.Now)
				if activate {
					sess.Activate()
				}
			} else {
				sess.RecordRefresh(params.Now)
			}
			sess.ApplyTokenJTI(artifacts.accessTokenJTI)
			sess.ApplyDeviceInfo(deviceState.DeviceID, deviceState.DeviceFingerprintHash)
		},
	)
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

// revokeSessionOnReplay handles replay attack detection by revoking the associated session.
// Returns nil if no replay detected. Revokes the session and returns nil on successful revocation.
// This is called when a token/code consumption fails with an "already used" error.
func revokeSessionOnReplay(
	ctx context.Context,
	stores txAuthStores,
	err error,
	sessionID id.SessionID,
	now time.Time,
) error {
	if !isAlreadyUsedError(err) {
		return nil
	}

	// Replay attack detected: revoke the session created with this token/code
	if revokeErr := stores.Sessions.RevokeSessionIfActive(ctx, sessionID, now); revokeErr != nil {
		return dErrors.Wrap(revokeErr, dErrors.CodeInternal, "failed to revoke session")
	}
	return nil
}

// isAlreadyUsedError checks if the error indicates a token/code was already used.
// Supports both sentinel errors (legacy) and domain errors (callback pattern).
func isAlreadyUsedError(err error) bool {
	// Legacy sentinel error
	if errors.Is(err, sentinel.ErrAlreadyUsed) {
		return true
	}
	// Domain error with "already used" message
	var de *dErrors.Error
	if errors.As(err, &de) {
		return strings.Contains(de.Message, "already used")
	}
	return false
}
