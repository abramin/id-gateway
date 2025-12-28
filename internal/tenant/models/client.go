package models

import (
	"time"

	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
)

// Client is the aggregate root for an OAuth 2.0 client registration.
//
// Invariants:
//   - Name is non-empty and at most 128 characters
//   - OAuthClientID is non-empty (the public client_id for OAuth flows)
//   - RedirectURIs, AllowedGrants, and AllowedScopes are non-empty
//   - Status is either active or inactive
//   - Status transitions: active ↔ inactive only
//   - TenantID is immutable after construction
//   - client_credentials grant requires IsConfidential() == true
type Client struct {
	ID               id.ClientID  `json:"id"`
	TenantID         id.TenantID  `json:"tenant_id"`
	Name             string       `json:"name"`
	OAuthClientID    string       `json:"client_id"`
	ClientSecretHash string       `json:"-"` // Never serialize - contains bcrypt hash
	RedirectURIs     []string     `json:"redirect_uris"`
	AllowedGrants    []GrantType  `json:"allowed_grants"`
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
	allowedGrants []GrantType,
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
	for _, grant := range allowedGrants {
		if !grant.IsValid() {
			return nil, dErrors.New(dErrors.CodeInvariantViolation, "invalid allowed_grant")
		}
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
// Returns an error if the transition is not allowed.
func (c *Client) Deactivate(now time.Time) error {
	if !c.Status.CanTransitionTo(ClientStatusInactive) {
		return dErrors.New(dErrors.CodeInvariantViolation, "client is already inactive")
	}
	c.Status = ClientStatusInactive
	c.UpdatedAt = now
	return nil
}

// Reactivate transitions the client to active status.
// Updates the timestamp to track when the transition occurred.
// Returns an error if the transition is not allowed.
func (c *Client) Reactivate(now time.Time) error {
	if !c.Status.CanTransitionTo(ClientStatusActive) {
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

// CanUseGrant checks if the client is allowed to use the specified grant type.
// Public clients cannot use client_credentials (requires secure secret storage).
func (c *Client) CanUseGrant(grant GrantType) bool {
	if grant.RequiresConfidentialClient() && !c.IsConfidential() {
		return false
	}
	return true
}
