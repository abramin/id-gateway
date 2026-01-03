package types

import id "credo/pkg/domain"

// ResolvedClient contains the client fields needed by auth flows.
// This is an auth-local DTO to avoid coupling to tenant models.
type ResolvedClient struct {
	ID            id.ClientID
	TenantID      id.TenantID
	OAuthClientID string
	RedirectURIs  []string
	AllowedScopes []string
	Active        bool
}

// IsActive returns whether the client is active.
func (c *ResolvedClient) IsActive() bool {
	return c.Active
}

// ResolvedTenant contains the tenant fields needed by auth flows.
// This is an auth-local DTO to avoid coupling to tenant models.
type ResolvedTenant struct {
	ID     id.TenantID
	Active bool
}

// IsActive returns whether the tenant is active.
func (t *ResolvedTenant) IsActive() bool {
	return t.Active
}
