package user

import (
	"context"

	authcontracts "credo/contracts/auth"
	"credo/internal/auth/models"
	id "credo/pkg/domain"
)

// Contract methods for InMemoryUserStore

// ListAllContract returns all users mapped to contract types for cross-module use.
func (s *InMemoryUserStore) ListAllContract(ctx context.Context) (map[string]*authcontracts.AdminUserView, error) {
	users, err := s.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	return mapUsersToContract(users), nil
}

// FindByIDContract returns a user by ID mapped to contract type.
func (s *InMemoryUserStore) FindByIDContract(ctx context.Context, userID id.UserID) (*authcontracts.AdminUserView, error) {
	user, err := s.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return mapUserToContract(user), nil
}

// Contract methods for PostgresStore

// ListAllContract returns all users mapped to contract types for cross-module use.
func (s *PostgresStore) ListAllContract(ctx context.Context) (map[string]*authcontracts.AdminUserView, error) {
	users, err := s.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	return mapUsersToContract(users), nil
}

// FindByIDContract returns a user by ID mapped to contract type.
func (s *PostgresStore) FindByIDContract(ctx context.Context, userID id.UserID) (*authcontracts.AdminUserView, error) {
	user, err := s.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return mapUserToContract(user), nil
}

// Shared mapping helpers

func mapUsersToContract(users map[id.UserID]*models.User) map[string]*authcontracts.AdminUserView {
	result := make(map[string]*authcontracts.AdminUserView, len(users))
	for k, u := range users {
		result[k.String()] = mapUserToContract(u)
	}
	return result
}

func mapUserToContract(u *models.User) *authcontracts.AdminUserView {
	return &authcontracts.AdminUserView{
		ID:        u.ID.String(),
		TenantID:  u.TenantID.String(),
		Email:     u.Email,
		FirstName: u.FirstName,
		LastName:  u.LastName,
		Verified:  u.Verified,
		Active:    u.IsActive(),
	}
}
