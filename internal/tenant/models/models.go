package models

import (
	"time"

	"github.com/google/uuid"
)

// Tenant represents an isolated identity boundary.
type Tenant struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// Client represents an OAuth relying party registered under a tenant.
type Client struct {
	ID               uuid.UUID `json:"id"`
	TenantID         uuid.UUID `json:"tenant_id"`
	Name             string    `json:"name"`
	ClientID         string    `json:"client_id"`
	ClientSecretHash string    `json:"client_secret_hash,omitempty"`
	RedirectURIs     []string  `json:"redirect_uris"`
	AllowedGrants    []string  `json:"allowed_grants"`
	AllowedScopes    []string  `json:"allowed_scopes"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// ClientResponse is returned to callers and includes the cleartext secret when rotated.
type ClientResponse struct {
	ID            uuid.UUID `json:"id"`
	TenantID      uuid.UUID `json:"tenant_id"`
	Name          string    `json:"name"`
	ClientID      string    `json:"client_id"`
	ClientSecret  string    `json:"client_secret,omitempty"`
	RedirectURIs  []string  `json:"redirect_uris"`
	AllowedGrants []string  `json:"allowed_grants"`
	AllowedScopes []string  `json:"allowed_scopes"`
	Status        string    `json:"status"`
}

// TenantDetails aggregates tenant metadata with counts for admin dashboards.
type TenantDetails struct {
	Tenant      *Tenant `json:"tenant"`
	UserCount   int     `json:"user_count"`
	ClientCount int     `json:"client_count"`
}
