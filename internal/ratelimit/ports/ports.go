// Package ports defines shared interfaces for the ratelimit module.
// Interfaces are placed here when consumed by multiple services to avoid duplication.
package ports

import (
	"context"
	"time"

	"credo/internal/ratelimit/models"
	id "credo/pkg/domain"
)

// BucketStore manages sliding window rate limit counters.
type BucketStore interface {
	// Allow checks if a single request is allowed and consumes one token if so.
	Allow(ctx context.Context, key string, limit int, window time.Duration) (*models.RateLimitResult, error)

	// AllowN checks if 'cost' requests are allowed and consumes that many tokens if so.
	AllowN(ctx context.Context, key string, cost, limit int, window time.Duration) (*models.RateLimitResult, error)

	// Reset clears the rate limit counter for a key.
	Reset(ctx context.Context, key string) error

	// GetCurrentCount returns the current request count in the window.
	GetCurrentCount(ctx context.Context, key string) (int, error)
}

// AllowlistStore manages rate limit bypass entries.
type AllowlistStore interface {
	// IsAllowlisted checks if an identifier should bypass rate limiting.
	IsAllowlisted(ctx context.Context, identifier string) (bool, error)

	// Add creates a new allowlist entry.
	Add(ctx context.Context, entry *models.AllowlistEntry) error

	// Remove deletes an allowlist entry.
	Remove(ctx context.Context, entryType models.AllowlistEntryType, identifier string) error

	// List returns all allowlist entries.
	List(ctx context.Context) ([]*models.AllowlistEntry, error)
}

// AuthLockoutStore manages authentication failure tracking and lockouts.
// Stores are pure I/O—domain logic (lock checks, state transitions) belongs in the service.
type AuthLockoutStore interface {
	// GetOrCreate retrieves an existing lockout record or creates a new one.
	// Returns a domain model that the service can mutate via domain methods.
	// The store does NOT increment counters—that's domain logic owned by the service.
	GetOrCreate(ctx context.Context, identifier string, now time.Time) (*models.AuthLockout, error)

	// Get retrieves the lockout record for an identifier. Returns nil if not found.
	Get(ctx context.Context, identifier string) (*models.AuthLockout, error)

	// Clear removes the lockout record for an identifier.
	Clear(ctx context.Context, identifier string) error

	// Update saves changes to a lockout record.
	Update(ctx context.Context, record *models.AuthLockout) error

	// ResetFailureCount resets window failure counts for records older than cutoff.
	// The cutoff time is provided by the caller (cleanup worker) to keep business rules out of store.
	ResetFailureCount(ctx context.Context, cutoff time.Time) (failuresReset int, err error)

	// ResetDailyFailures resets daily failure counts for records older than cutoff.
	// The cutoff time is provided by the caller (cleanup worker) to keep business rules out of store.
	ResetDailyFailures(ctx context.Context, cutoff time.Time) (failuresReset int, err error)
}

// QuotaStore manages API key usage quotas.
type QuotaStore interface {
	// GetQuota retrieves quota information for an API key.
	GetQuota(ctx context.Context, apiKeyID id.APIKeyID) (*models.APIKeyQuota, error)

	// IncrementUsage adds to the usage counter for an API key.
	IncrementUsage(ctx context.Context, apiKeyID id.APIKeyID, count int) (*models.APIKeyQuota, error)

	// ResetQuota clears the usage counter for an API key.
	ResetQuota(ctx context.Context, apiKeyID id.APIKeyID) error

	// ListQuotas returns all quota records.
	ListQuotas(ctx context.Context) ([]*models.APIKeyQuota, error)

	// UpdateTier changes the quota tier for an API key.
	UpdateTier(ctx context.Context, apiKeyID id.APIKeyID, tier models.QuotaTier) error
}

// GlobalThrottleStore manages global request throttling counters.
type GlobalThrottleStore interface {
	// IncrementGlobal increments the global counter and checks if blocked.
	IncrementGlobal(ctx context.Context) (count int, blocked bool, err error)

	// GetGlobalCount returns the current global request count.
	GetGlobalCount(ctx context.Context) (count int, err error)
}

// ClientLookup provides OAuth client type information.
type ClientLookup interface {
	// IsConfidentialClient checks if a client is a confidential (server-side) client.
	IsConfidentialClient(ctx context.Context, clientID string) (bool, error)
}
