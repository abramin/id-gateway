package store

import (
	"context"

	"credo/internal/tenant/models"
	id "credo/pkg/domain"
)

// TenantStore persists tenant records.
type TenantStore interface {
	Create(ctx context.Context, tenant *models.Tenant) error
	CreateIfNameAvailable(ctx context.Context, tenant *models.Tenant) error
	Update(ctx context.Context, tenant *models.Tenant) error
	FindByID(ctx context.Context, tenantID id.TenantID) (*models.Tenant, error)
	FindByName(ctx context.Context, name string) (*models.Tenant, error)
	Count(ctx context.Context) (int, error)
}

// ClientStore persists client application registrations.
type ClientStore interface {
	Create(ctx context.Context, client *models.Client) error
	Update(ctx context.Context, client *models.Client) error
	FindByID(ctx context.Context, clientID id.ClientID) (*models.Client, error)
	FindByTenantAndID(ctx context.Context, tenantID id.TenantID, clientID id.ClientID) (*models.Client, error)
	FindByClientID(ctx context.Context, oauthClientID string) (*models.Client, error)
	CountByTenant(ctx context.Context, tenantID id.TenantID) (int, error)
}

// UserCounter optionally provides per-tenant user counts.
type UserCounter interface {
	CountByTenant(ctx context.Context, tenantID id.TenantID) (int, error)
}
