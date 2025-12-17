package service

import (
	"context"
	"time"

	"credo/internal/audit"
	"credo/internal/ratelimit/models"
)

// BucketStore defines the persistence interface for rate limit buckets/counters.
// Per PRD-017 TR-1: RateLimiter interface with Allow, AllowN, Reset operations.
type BucketStore interface {
	// Allow checks if a request is allowed and increments the counter.
	// Returns the rate limit result with remaining tokens and reset time.
	// Per PRD-017 TR-1: Allow(ctx, key, limit, window) -> (allowed, remaining, resetAt, err)
	Allow(ctx context.Context, key string, limit int, window time.Duration) (*models.RateLimitResult, error)

	// AllowN checks if a request with custom cost is allowed.
	// Per PRD-017 TR-1: AllowN for operations that consume multiple tokens.
	AllowN(ctx context.Context, key string, cost int, limit int, window time.Duration) (*models.RateLimitResult, error)

	// Reset clears the rate limit counter for a key.
	// Per PRD-017 TR-1: Admin operation to reset limits.
	Reset(ctx context.Context, key string) error

	// GetCurrentCount returns the current request count for a key.
	// Used for monitoring and admin display.
	GetCurrentCount(ctx context.Context, key string) (int, error)
}

// AllowlistStore defines the persistence interface for rate limit allowlist.
// Per PRD-017 FR-4: Allowlist management for IPs and users.
type AllowlistStore interface {
	// Add adds an identifier to the allowlist.
	Add(ctx context.Context, entry *models.AllowlistEntry) error

	// Remove removes an identifier from the allowlist.
	Remove(ctx context.Context, entryType models.AllowlistEntryType, identifier string) error

	// IsAllowlisted checks if an identifier is in the allowlist and not expired.
	// Per PRD-017 TR-1: IsAllowlisted(ctx, identifier) -> (bool, error)
	IsAllowlisted(ctx context.Context, identifier string) (bool, error)

	// List returns all active allowlist entries.
	List(ctx context.Context) ([]*models.AllowlistEntry, error)
}

// AuthLockoutStore defines the persistence interface for authentication lockouts.
// Per PRD-017 FR-2b: OWASP authentication-specific protections.
type AuthLockoutStore interface {
	// RecordFailure records a failed authentication attempt.
	RecordFailure(ctx context.Context, identifier string) (*models.AuthLockout, error)

	// GetLockout retrieves the current lockout state for an identifier.
	GetLockout(ctx context.Context, identifier string) (*models.AuthLockout, error)

	// ClearLockout clears the lockout state after successful authentication.
	ClearLockout(ctx context.Context, identifier string) error

	// IsLocked checks if an identifier is currently locked out.
	IsLocked(ctx context.Context, identifier string) (bool, *time.Time, error)
}

// QuotaStore defines the persistence interface for partner API quotas.
// Per PRD-017 FR-5: Partner API quota management.
type QuotaStore interface {
	// GetQuota retrieves the quota for an API key.
	GetQuota(ctx context.Context, apiKeyID string) (*models.APIKeyQuota, error)

	// IncrementUsage increments the usage counter for an API key.
	IncrementUsage(ctx context.Context, apiKeyID string, count int) (*models.APIKeyQuota, error)

	// SetQuota sets or updates the quota configuration for an API key.
	SetQuota(ctx context.Context, quota *models.APIKeyQuota) error
}

// AuditPublisher defines the interface for publishing audit events.
// Per PRD-017: Rate limit violations emit audit events.
type AuditPublisher interface {
	Emit(ctx context.Context, event audit.Event) error
}

// GlobalThrottleStore defines the interface for global request throttling.
// Per PRD-017 FR-6: DDoS protection via global limits.
type GlobalThrottleStore interface {
	// IncrementGlobal increments the global request counter.
	// Returns current count and whether limit is exceeded.
	IncrementGlobal(ctx context.Context) (int, bool, error)

	// GetGlobalCount returns the current global request count.
	GetGlobalCount(ctx context.Context) (int, error)
}
