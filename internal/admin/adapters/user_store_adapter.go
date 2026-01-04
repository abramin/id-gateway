package adapters

import (
	"context"

	authcontracts "credo/contracts/auth"
	"credo/internal/admin/types"
	id "credo/pkg/domain"
)

// AuthUserContractStore is the interface that auth user stores implement for contract access.
// Uses contract types to eliminate dependency on internal auth models.
type AuthUserContractStore interface {
	ListAllContract(ctx context.Context) (map[string]*authcontracts.AdminUserView, error)
	FindByIDContract(ctx context.Context, userID id.UserID) (*authcontracts.AdminUserView, error)
}

// UserStoreAdapter adapts an auth user store to admin's UserStore interface.
type UserStoreAdapter struct {
	store AuthUserContractStore
}

// NewUserStoreAdapter creates a new adapter wrapping an auth user store.
func NewUserStoreAdapter(store AuthUserContractStore) *UserStoreAdapter {
	return &UserStoreAdapter{store: store}
}

// ListAll returns all users mapped to admin types.
func (a *UserStoreAdapter) ListAll(ctx context.Context) (map[id.UserID]*types.AdminUser, error) {
	users, err := a.store.ListAllContract(ctx)
	if err != nil {
		return nil, err
	}

	result := make(map[id.UserID]*types.AdminUser, len(users))
	for k, u := range users {
		userID, _ := id.ParseUserID(k) //nolint:errcheck // IDs from validated source
		result[userID] = mapUser(u)
	}
	return result, nil
}

// FindByID returns a user by ID mapped to admin type.
func (a *UserStoreAdapter) FindByID(ctx context.Context, userID id.UserID) (*types.AdminUser, error) {
	user, err := a.store.FindByIDContract(ctx, userID)
	if err != nil {
		return nil, err
	}
	return mapUser(user), nil
}

func mapUser(u *authcontracts.AdminUserView) *types.AdminUser {
	// IDs come from auth store which validates them, so parsing should never fail.
	userID, _ := id.ParseUserID(u.ID)       //nolint:errcheck // IDs from validated source
	tenantID, _ := id.ParseTenantID(u.TenantID) //nolint:errcheck // IDs from validated source

	return &types.AdminUser{
		ID:        userID,
		TenantID:  tenantID,
		Email:     u.Email,
		FirstName: u.FirstName,
		LastName:  u.LastName,
		Verified:  u.Verified,
		Active:    u.Active,
	}
}
