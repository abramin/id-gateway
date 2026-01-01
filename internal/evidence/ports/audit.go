// Package ports defines shared interfaces for the evidence module.
// These ports are consumed by both the vc and registry submodules.
package ports

import (
	"context"

	"credo/pkg/platform/audit"
)

// AuditPublisher emits audit events for evidence-related actions.
// Implementations should handle audit failures appropriately based on
// the criticality of the operation (fail-closed for sanctions, best-effort for others).
type AuditPublisher interface {
	Emit(ctx context.Context, event audit.Event) error
}
