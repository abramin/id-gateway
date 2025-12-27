package ports

import (
	"context"

	"credo/pkg/platform/audit"
)

// AuditPort defines the interface for audit event emission.
// This allows the registry service to emit audit events without
// depending directly on the audit publisher implementation.
type AuditPort interface {
	// Emit publishes an audit event.
	// Returns nil on success, error on failure (e.g., buffer full).
	Emit(ctx context.Context, event audit.Event) error
}
