package adapters

import (
	"context"

	tenantcontracts "credo/contracts/tenant"
	"credo/internal/auth/types"
	id "credo/pkg/domain"
)

// tenantContractProvider is the interface that tenant service implements.
// Defined locally to avoid coupling auth adapters to tenant service package.
// Uses contract types to eliminate dependency on internal tenant models.
type tenantContractProvider interface {
	ResolveClientContract(ctx context.Context, clientID string) (*tenantcontracts.ResolvedClient, *tenantcontracts.ResolvedTenant, error)
}

// TenantClientResolver adapts tenant service to auth.ClientResolver.
// This adapter maps tenant contracts to auth-local DTOs at the boundary.
type TenantClientResolver struct {
	tenantSvc tenantContractProvider
}

// NewTenantClientResolver creates a new adapter wrapping the tenant service.
func NewTenantClientResolver(svc tenantContractProvider) *TenantClientResolver {
	return &TenantClientResolver{tenantSvc: svc}
}

// ResolveClient resolves a client by OAuth client ID and maps to auth types.
func (a *TenantClientResolver) ResolveClient(ctx context.Context, clientID string) (*types.ResolvedClient, *types.ResolvedTenant, error) {
	client, tenant, err := a.tenantSvc.ResolveClientContract(ctx, clientID)
	if err != nil {
		return nil, nil, err
	}

	return mapClient(client), mapTenant(tenant), nil
}

func mapClient(c *tenantcontracts.ResolvedClient) *types.ResolvedClient {
	// IDs come from tenant service which validates them, so parsing should never fail.
	// If it does, it indicates a bug in the contract producer.
	clientID, _ := id.ParseClientID(c.ID)
	tenantID, _ := id.ParseTenantID(c.TenantID)

	return &types.ResolvedClient{
		ID:            clientID,
		TenantID:      tenantID,
		OAuthClientID: c.OAuthClientID,
		RedirectURIs:  c.RedirectURIs,
		AllowedScopes: c.AllowedScopes,
		Active:        c.Active,
	}
}

func mapTenant(t *tenantcontracts.ResolvedTenant) *types.ResolvedTenant {
	// ID comes from tenant service which validates it, so parsing should never fail.
	tenantID, _ := id.ParseTenantID(t.ID)

	return &types.ResolvedTenant{
		ID:     tenantID,
		Active: t.Active,
	}
}
