package tenant

// Package tenant hosts the stable, minimal DTOs shared across services for
// tenant/client resolution. Keep these versioned independently from internal
// tenant schemas or persistence models.

// ContractVersion identifies the contract schema version for compatibility checks.
// Bump on breaking changes to the shapes below; consumers can pin or roll forward.
const ContractVersion = "v0.1.0"

// ResolvedClient is the minimal client info needed by consuming modules (e.g., auth).
// Contains only OAuth-relevant fields, no internal metadata.
type ResolvedClient struct {
	ID            string
	TenantID      string
	OAuthClientID string
	RedirectURIs  []string
	AllowedScopes []string
	Active        bool
}

// ResolvedTenant is the minimal tenant info needed by consuming modules.
type ResolvedTenant struct {
	ID     string
	Active bool
}
