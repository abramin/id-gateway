package adapters

import (
	"context"

	authcontracts "credo/contracts/auth"
	"credo/internal/admin/types"
	id "credo/pkg/domain"
)

// AuthSessionContractStore is the interface that auth session stores implement for contract access.
// Uses contract types to eliminate dependency on internal auth models.
type AuthSessionContractStore interface {
	ListAllContract(ctx context.Context) (map[string]*authcontracts.AdminSessionView, error)
	ListByUserContract(ctx context.Context, userID id.UserID) ([]*authcontracts.AdminSessionView, error)
}

// SessionStoreAdapter adapts an auth session store to admin's SessionStore interface.
type SessionStoreAdapter struct {
	store AuthSessionContractStore
}

// NewSessionStoreAdapter creates a new adapter wrapping an auth session store.
func NewSessionStoreAdapter(store AuthSessionContractStore) *SessionStoreAdapter {
	return &SessionStoreAdapter{store: store}
}

// ListAll returns all sessions mapped to admin types.
func (a *SessionStoreAdapter) ListAll(ctx context.Context) (map[id.SessionID]*types.AdminSession, error) {
	sessions, err := a.store.ListAllContract(ctx)
	if err != nil {
		return nil, err
	}

	result := make(map[id.SessionID]*types.AdminSession, len(sessions))
	for k, s := range sessions {
		sessionID, _ := id.ParseSessionID(k) //nolint:errcheck // IDs from validated source
		result[sessionID] = mapSession(s)
	}
	return result, nil
}

// ListByUser returns sessions for a user mapped to admin types.
func (a *SessionStoreAdapter) ListByUser(ctx context.Context, userID id.UserID) ([]*types.AdminSession, error) {
	sessions, err := a.store.ListByUserContract(ctx, userID)
	if err != nil {
		return nil, err
	}

	result := make([]*types.AdminSession, len(sessions))
	for i, s := range sessions {
		result[i] = mapSession(s)
	}
	return result, nil
}

func mapSession(s *authcontracts.AdminSessionView) *types.AdminSession {
	// IDs come from auth store which validates them, so parsing should never fail.
	sessionID, _ := id.ParseSessionID(s.ID) //nolint:errcheck // IDs from validated source
	userID, _ := id.ParseUserID(s.UserID)   //nolint:errcheck // IDs from validated source

	return &types.AdminSession{
		ID:        sessionID,
		UserID:    userID,
		CreatedAt: s.CreatedAt,
		ExpiresAt: s.ExpiresAt,
		Active:    s.Active,
	}
}
