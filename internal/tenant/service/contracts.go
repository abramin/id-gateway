package service

import (
	"context"

	tenantcontracts "credo/contracts/tenant"
)

// ResolveClientContract resolves a client and its tenant returning contract types
// for cross-module use. This method wraps ResolveClient and maps to stable contract
// types, allowing consuming modules (e.g., auth) to depend on contracts rather than
// internal models.
func (s *ClientService) ResolveClientContract(ctx context.Context, clientID string) (*tenantcontracts.ResolvedClient, *tenantcontracts.ResolvedTenant, error) {
	client, tenant, err := s.ResolveClient(ctx, clientID)
	if err != nil {
		return nil, nil, err
	}

	return &tenantcontracts.ResolvedClient{
			ID:            client.ID.String(),
			TenantID:      client.TenantID.String(),
			OAuthClientID: client.OAuthClientID,
			RedirectURIs:  client.RedirectURIs,
			AllowedScopes: client.AllowedScopes,
			Active:        client.IsActive(),
		}, &tenantcontracts.ResolvedTenant{
			ID:     tenant.ID.String(),
			Active: tenant.IsActive(),
		}, nil
}
