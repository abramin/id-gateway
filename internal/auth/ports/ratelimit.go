package ports

import (
	"context"
	"time"
)

// RateLimitPort defines the interface for auth rate limiting operations.
// This port allows the auth handler to check rate limits and record failures
// without depending on the ratelimit service implementation.
// When splitting into microservices, this can be replaced with a gRPC adapter
// without changing the auth handler.
type RateLimitPort interface {
	CheckAuthRateLimit(ctx context.Context, identifier, ip string) (*AuthRateLimitResult, error)
	RecordAuthFailure(ctx context.Context, identifier, ip string) (*AuthLockoutState, error)
	ClearAuthFailures(ctx context.Context, identifier, ip string) error
}

type AuthRateLimitResult struct {
	Allowed    bool
	Remaining  int
	RetryAfter int // seconds until retry is allowed
	ResetAt    time.Time
}

type AuthLockoutState struct {
	FailureCount    int
	LockedUntil     *time.Time
	RequiresCaptcha bool
}
