package admin

import (
	"context"

	"credo/internal/ratelimit/models"
	"credo/pkg/platform/audit"
)

// AllowlistStore defines the persistence interface for rate limit allowlist.
type AllowlistStore interface {
	// Add adds an identifier to the allowlist.
	Add(ctx context.Context, entry *models.AllowlistEntry) error

	// Remove removes an identifier from the allowlist.
	Remove(ctx context.Context, entryType models.AllowlistEntryType, identifier string) error

	// List returns all active allowlist entries.
	List(ctx context.Context) ([]*models.AllowlistEntry, error)
}

// BucketStore defines the persistence interface for rate limit bucket operations.
type BucketStore interface {
	// Reset clears the rate limit counter for a key.
	Reset(ctx context.Context, key string) error

	// GetCurrentCount returns the current request count for a key.
	GetCurrentCount(ctx context.Context, key string) (int, error)
}

// AuditPublisher defines the interface for publishing audit events.
type AuditPublisher interface {
	Emit(ctx context.Context, event audit.Event) error
}
