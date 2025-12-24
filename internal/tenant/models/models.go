package models

import (
	"time"

	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
)

type Tenant struct {
	ID        id.TenantID  `json:"id"`
	Name      string       `json:"name"`
	Status    TenantStatus `json:"status"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
}

func (t *Tenant) IsActive() bool {
	return t.Status == TenantStatusActive
}

// Deactivate transitions the tenant to inactive status.
// Updates the timestamp to track when the transition occurred.
// Returns an error if the tenant is already inactive.
func (t *Tenant) Deactivate(now time.Time) error {
	if !t.IsActive() {
		return dErrors.New(dErrors.CodeInvariantViolation, "tenant is already inactive")
	}
	t.Status = TenantStatusInactive
	t.UpdatedAt = now
	return nil
}

// Reactivate transitions the tenant to active status.
// Updates the timestamp to track when the transition occurred.
// Returns an error if the tenant is already active.
func (t *Tenant) Reactivate(now time.Time) error {
	if t.IsActive() {
		return dErrors.New(dErrors.CodeInvariantViolation, "tenant is already active")
	}
	t.Status = TenantStatusActive
	t.UpdatedAt = now
	return nil
}

func NewTenant(tenantID id.TenantID, name string) (*Tenant, error) {
	if name == "" {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "tenant name cannot be empty")
	}
	if len(name) > 128 {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "tenant name must be 128 characters or less")
	}
	now := time.Now()
	return &Tenant{
		ID:        tenantID,
		Name:      name,
		Status:    TenantStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

type Client struct {
	ID               id.ClientID  `json:"id"`
	TenantID         id.TenantID  `json:"tenant_id"`
	Name             string       `json:"name"`
	OAuthClientID    string       `json:"client_id"`
	ClientSecretHash string       `json:"-"` // Never serialize - contains bcrypt hash
	RedirectURIs     []string     `json:"redirect_uris"`
	AllowedGrants    []string     `json:"allowed_grants"`
	AllowedScopes    []string     `json:"allowed_scopes"`
	Status           ClientStatus `json:"status"`
	CreatedAt        time.Time    `json:"created_at"`
	UpdatedAt        time.Time    `json:"updated_at"`
}

func NewClient(
	clientID id.ClientID,
	tenantID id.TenantID,
	name string,
	oauthClientID string,
	clientSecretHash string,
	redirectURIs []string,
	allowedGrants []string,
	allowedScopes []string,
	now time.Time,
) (*Client, error) {
	if name == "" {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "client name cannot be empty")
	}
	if len(name) > 128 {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "client name must be 128 characters or less")
	}
	if oauthClientID == "" {
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
		ID:               clientID,
		TenantID:         tenantID,
		Name:             name,
		OAuthClientID:    oauthClientID,
		ClientSecretHash: clientSecretHash,
		RedirectURIs:     redirectURIs,
		AllowedGrants:    allowedGrants,
		AllowedScopes:    allowedScopes,
		Status:           ClientStatusActive,
		CreatedAt:        now,
		UpdatedAt:        now,
	}, nil
}

func (c *Client) IsActive() bool {
	return c.Status == ClientStatusActive
}

// Deactivate transitions the client to inactive status.
// Updates the timestamp to track when the transition occurred.
// Returns an error if the client is already inactive.
func (c *Client) Deactivate(now time.Time) error {
	if !c.IsActive() {
		return dErrors.New(dErrors.CodeInvariantViolation, "client is already inactive")
	}
	c.Status = ClientStatusInactive
	c.UpdatedAt = now
	return nil
}

// Reactivate transitions the client to active status.
// Updates the timestamp to track when the transition occurred.
// Returns an error if the client is already active.
func (c *Client) Reactivate(now time.Time) error {
	if c.IsActive() {
		return dErrors.New(dErrors.CodeInvariantViolation, "client is already active")
	}
	c.Status = ClientStatusActive
	c.UpdatedAt = now
	return nil
}

// Confidential clients are server-side apps with secure secret storage.
// Public clients are SPAs/mobile apps that cannot securely store secrets.
func (c *Client) IsConfidential() bool {
	return c.ClientSecretHash != ""
}

// TenantDetails aggregates tenant metadata with counts for admin dashboards.
// Internal type - converted to TenantDetailsResponse for HTTP serialization.
type TenantDetails struct {
	ID          id.TenantID
	Name        string
	Status      TenantStatus
	CreatedAt   time.Time
	UpdatedAt   time.Time
	UserCount   int
	ClientCount int
}
