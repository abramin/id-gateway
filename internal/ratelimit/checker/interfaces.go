package checker

import (
	"context"
	"time"

	"credo/internal/ratelimit/models"
	"credo/pkg/platform/audit"
)

// BucketStore defines the persistence interface for rate limit buckets/counters.
type BucketStore interface {
	// Allow checks if a request is allowed and increments the counter.
	Allow(ctx context.Context, key string, limit int, window time.Duration) (*models.RateLimitResult, error)

	// AllowN checks if a request with custom cost is allowed.
	AllowN(ctx context.Context, key string, cost, limit int, window time.Duration) (*models.RateLimitResult, error)
}

// AllowlistStore defines the read-only interface for checking allowlist membership.
type AllowlistStore interface {
	// IsAllowlisted checks if an identifier is in the allowlist and not expired.
	IsAllowlisted(ctx context.Context, identifier string) (bool, error)
}

// AuthLockoutStore defines the persistence interface for authentication lockouts.
type AuthLockoutStore interface {
	// RecordFailure records a failed authentication attempt.
	RecordFailure(ctx context.Context, identifier string) (*models.AuthLockout, error)

	// Get retrieves the current lockout state for an identifier.
	Get(ctx context.Context, identifier string) (*models.AuthLockout, error)

	// Clear clears the lockout state after successful authentication.
	Clear(ctx context.Context, identifier string) error

	// IsLocked checks if an identifier is currently locked out.
	IsLocked(ctx context.Context, identifier string) (bool, *time.Time, error)
}

// QuotaStore defines the persistence interface for partner API quotas.
type QuotaStore interface {
	// GetQuota retrieves the quota for an API key.
	GetQuota(ctx context.Context, apiKeyID string) (*models.APIKeyQuota, error)

	// IncrementUsage increments the usage counter for an API key.
	IncrementUsage(ctx context.Context, apiKeyID string, count int) (*models.APIKeyQuota, error)
}

// GlobalThrottleStore defines the interface for global request throttling.
type GlobalThrottleStore interface {
	// IncrementGlobal increments the global request counter.
	// Returns current count and whether limit is exceeded.
	IncrementGlobal(ctx context.Context) (int, bool, error)

	// GetGlobalCount returns the current global request count.
	GetGlobalCount(ctx context.Context) (int, error)
}

// AuditPublisher defines the interface for publishing audit events.
type AuditPublisher interface {
	Emit(ctx context.Context, event audit.Event) error
}
