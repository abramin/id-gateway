package models

import id "credo/pkg/domain"

// Domain events capture what happened in the tenant domain.
// These are pure data structures with no behavior - the application layer
// is responsible for publishing them to the audit system.

// TenantCreated is emitted when a new tenant is registered.
type TenantCreated struct {
	TenantID id.TenantID
}

// TenantDeactivated is emitted when a tenant is suspended.
type TenantDeactivated struct {
	TenantID id.TenantID
}

// TenantReactivated is emitted when a suspended tenant is restored.
type TenantReactivated struct {
	TenantID id.TenantID
}

// ClientCreated is emitted when a new OAuth client is registered.
type ClientCreated struct {
	TenantID   id.TenantID
	ClientID   id.ClientID
	ClientName string
}

// ClientDeactivated is emitted when a client is blocked from OAuth flows.
type ClientDeactivated struct {
	TenantID id.TenantID
	ClientID id.ClientID
}

// ClientReactivated is emitted when a blocked client is restored.
type ClientReactivated struct {
	TenantID id.TenantID
	ClientID id.ClientID
}

// ClientSecretRotated is emitted when a client's secret is regenerated.
type ClientSecretRotated struct {
	TenantID id.TenantID
	ClientID id.ClientID
}
