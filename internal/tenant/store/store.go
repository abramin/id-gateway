package store

import (
	"context"

	"github.com/google/uuid"

	"credo/internal/tenant/models"
)

// TenantStore persists tenant records.
type TenantStore interface {
	Create(ctx context.Context, tenant *models.Tenant) error
	CreateIfNameAvailable(ctx context.Context, tenant *models.Tenant) error
	Update(ctx context.Context, tenant *models.Tenant) error
	FindByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error)
	FindByName(ctx context.Context, name string) (*models.Tenant, error)
	Count(ctx context.Context) (int, error)
}

// ClientStore persists client application registrations.
type ClientStore interface {
	Create(ctx context.Context, client *models.Client) error
	Update(ctx context.Context, client *models.Client) error
	FindByID(ctx context.Context, id uuid.UUID) (*models.Client, error)
	FindByTenantAndID(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*models.Client, error)
	FindByClientID(ctx context.Context, clientID string) (*models.Client, error)
	CountByTenant(ctx context.Context, tenantID uuid.UUID) (int, error)
}

// UserCounter optionally provides per-tenant user counts.
type UserCounter interface {
	CountByTenant(ctx context.Context, tenantID uuid.UUID) (int, error)
}
