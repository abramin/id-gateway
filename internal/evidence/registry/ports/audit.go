package ports

import (
	"context"

	"credo/pkg/platform/audit"
)

// AuditPort defines the interface for audit event publishing.
// This is a hexagonal architecture port - the domain layer depends on this interface,
// and adapters implement it.
type AuditPort interface {
	// Emit publishes an audit event. Returns error if the audit system is unavailable.
	Emit(ctx context.Context, event audit.Event) error
}
