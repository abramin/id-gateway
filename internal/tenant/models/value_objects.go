package models

import domain "credo/pkg/domain"

// TenantStatus represents the lifecycle state of a tenant.
// Tenants can be active (operational) or inactive (suspended).
//
// State machine:
//
//	active ↔ inactive
//
// Invariant: Only these two states are valid; no terminal states exist.
type TenantStatus string

const (
	// TenantStatusActive indicates the tenant is operational and clients can use OAuth flows.
	TenantStatusActive TenantStatus = "active"
	// TenantStatusInactive indicates the tenant is suspended and all OAuth flows are blocked.
	TenantStatusInactive TenantStatus = "inactive"
)

// IsValid returns true if the status is a known valid value.
func (s TenantStatus) IsValid() bool {
	return s == TenantStatusActive || s == TenantStatusInactive
}

// String returns the string representation of the status.
func (s TenantStatus) String() string {
	return string(s)
}

// CanTransitionTo returns true if the status can transition to the target status.
// Tenants can toggle between active and inactive states.
func (s TenantStatus) CanTransitionTo(target TenantStatus) bool {
	switch s {
	case TenantStatusActive:
		return target == TenantStatusInactive
	case TenantStatusInactive:
		return target == TenantStatusActive
	}
	return false
}

// ClientStatus represents the lifecycle state of an OAuth client.
// Clients can be active (operational) or inactive (blocked from OAuth flows).
type ClientStatus string

const (
	// ClientStatusActive indicates the client can participate in OAuth flows.
	ClientStatusActive ClientStatus = "active"
	// ClientStatusInactive indicates the client is blocked from all OAuth flows.
	ClientStatusInactive ClientStatus = "inactive"
)

// IsValid returns true if the status is a known valid value.
func (s ClientStatus) IsValid() bool {
	return s == ClientStatusActive || s == ClientStatusInactive
}

// String returns the string representation of the status.
func (s ClientStatus) String() string {
	return string(s)
}

// CanTransitionTo returns true if the status can transition to the target status.
// Clients can toggle between active and inactive states.
func (s ClientStatus) CanTransitionTo(target ClientStatus) bool {
	switch s {
	case ClientStatusActive:
		return target == ClientStatusInactive
	case ClientStatusInactive:
		return target == ClientStatusActive
	}
	return false
}

// GrantType represents an OAuth 2.0 grant type that a client can use.
//
// Invariant: client_credentials requires a confidential client (one with a secret).
// Public clients (SPAs, mobile apps) cannot use client_credentials.
type GrantType = domain.GrantType

const (
	// GrantTypeAuthorizationCode is the standard OAuth 2.0 authorization code flow.
	GrantTypeAuthorizationCode = domain.GrantTypeAuthorizationCode
	// GrantTypeRefreshToken allows exchanging refresh tokens for new access tokens.
	GrantTypeRefreshToken = domain.GrantTypeRefreshToken
	// GrantTypeClientCredentials is for machine-to-machine authentication (confidential clients only).
	GrantTypeClientCredentials = domain.GrantTypeClientCredentials
)
