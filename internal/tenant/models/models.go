package models

import (
	"time"

	"github.com/google/uuid"

	dErrors "credo/pkg/domain-errors"
)

// Tenant represents an isolated identity boundary.
type Tenant struct {
	ID        uuid.UUID    `json:"id"`
	Name      string       `json:"name"`
	Status    TenantStatus `json:"status"`
	CreatedAt time.Time    `json:"created_at"`
}

// NewTenant creates a Tenant with domain invariant checks.
func NewTenant(id uuid.UUID, name string) (*Tenant, error) {
	if id == uuid.Nil {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "tenant ID cannot be nil")
	}
	if name == "" {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "tenant name cannot be empty")
	}
	if len(name) > 128 {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "tenant name must be 128 characters or less")
	}
	return &Tenant{
		ID:        id,
		Name:      name,
		Status:    TenantStatusActive,
		CreatedAt: time.Now(),
	}, nil
}

// Client represents an OAuth relying party registered under a tenant.
type Client struct {
	ID               uuid.UUID    `json:"id"`
	TenantID         uuid.UUID    `json:"tenant_id"`
	Name             string       `json:"name"`
	ClientID         string       `json:"client_id"`
	ClientSecretHash string       `json:"client_secret_hash,omitempty"`
	RedirectURIs     []string     `json:"redirect_uris"`
	AllowedGrants    []string     `json:"allowed_grants"`
	AllowedScopes    []string     `json:"allowed_scopes"`
	Status           ClientStatus `json:"status"`
	CreatedAt        time.Time    `json:"created_at"`
	UpdatedAt        time.Time    `json:"updated_at"`
}

// NewClient creates a Client with domain invariant checks.
func NewClient(
	id uuid.UUID,
	tenantID uuid.UUID,
	name string,
	clientID string,
	clientSecretHash string,
	redirectURIs []string,
	allowedGrants []string,
	allowedScopes []string,
	now time.Time,
) (*Client, error) {
	if id == uuid.Nil {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "client ID cannot be nil")
	}
	if tenantID == uuid.Nil {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "tenant ID cannot be nil")
	}
	if name == "" {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "client name cannot be empty")
	}
	if len(name) > 128 {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "client name must be 128 characters or less")
	}
	if clientID == "" {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "client_id cannot be empty")
	}
	if len(redirectURIs) == 0 {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "redirect_uris cannot be empty")
	}
	if len(allowedGrants) == 0 {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "allowed_grants cannot be empty")
	}
	if len(allowedScopes) == 0 {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "allowed_scopes cannot be empty")
	}
	return &Client{
		ID:               id,
		TenantID:         tenantID,
		Name:             name,
		ClientID:         clientID,
		ClientSecretHash: clientSecretHash,
		RedirectURIs:     redirectURIs,
		AllowedGrants:    allowedGrants,
		AllowedScopes:    allowedScopes,
		Status:           ClientStatusActive,
		CreatedAt:        now,
		UpdatedAt:        now,
	}, nil
}

// IsActive returns true if the client is active.
func (c *Client) IsActive() bool {
	return c.Status == ClientStatusActive
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
