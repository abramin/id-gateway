package session

import (
	"context"

	authcontracts "credo/contracts/auth"
	"credo/internal/auth/models"
	id "credo/pkg/domain"
)

// Contract methods for InMemorySessionStore

// ListAllContract returns all sessions mapped to contract types for cross-module use.
func (s *InMemorySessionStore) ListAllContract(ctx context.Context) (map[string]*authcontracts.AdminSessionView, error) {
	sessions, err := s.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	return mapSessionsToContract(sessions), nil
}

// ListByUserContract returns sessions for a user mapped to contract types.
func (s *InMemorySessionStore) ListByUserContract(ctx context.Context, userID id.UserID) ([]*authcontracts.AdminSessionView, error) {
	sessions, err := s.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	return mapSessionSliceToContract(sessions), nil
}

// Contract methods for RedisStore

// ListAllContract returns all sessions mapped to contract types for cross-module use.
func (s *RedisStore) ListAllContract(ctx context.Context) (map[string]*authcontracts.AdminSessionView, error) {
	sessions, err := s.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	return mapSessionsToContract(sessions), nil
}

// ListByUserContract returns sessions for a user mapped to contract types.
func (s *RedisStore) ListByUserContract(ctx context.Context, userID id.UserID) ([]*authcontracts.AdminSessionView, error) {
	sessions, err := s.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	return mapSessionSliceToContract(sessions), nil
}

// Contract methods for PostgresStore

// ListAllContract returns all sessions mapped to contract types for cross-module use.
func (s *PostgresStore) ListAllContract(ctx context.Context) (map[string]*authcontracts.AdminSessionView, error) {
	sessions, err := s.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	return mapSessionsToContract(sessions), nil
}

// ListByUserContract returns sessions for a user mapped to contract types.
func (s *PostgresStore) ListByUserContract(ctx context.Context, userID id.UserID) ([]*authcontracts.AdminSessionView, error) {
	sessions, err := s.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	return mapSessionSliceToContract(sessions), nil
}

// Shared mapping helpers

func mapSessionsToContract(sessions map[id.SessionID]*models.Session) map[string]*authcontracts.AdminSessionView {
	result := make(map[string]*authcontracts.AdminSessionView, len(sessions))
	for k, s := range sessions {
		result[k.String()] = mapSessionToContract(s)
	}
	return result
}

func mapSessionSliceToContract(sessions []*models.Session) []*authcontracts.AdminSessionView {
	result := make([]*authcontracts.AdminSessionView, len(sessions))
	for i, s := range sessions {
		result[i] = mapSessionToContract(s)
	}
	return result
}

func mapSessionToContract(s *models.Session) *authcontracts.AdminSessionView {
	return &authcontracts.AdminSessionView{
		ID:        s.ID.String(),
		UserID:    s.UserID.String(),
		CreatedAt: s.CreatedAt,
		ExpiresAt: s.ExpiresAt,
		Active:    s.IsActive(),
	}
}
