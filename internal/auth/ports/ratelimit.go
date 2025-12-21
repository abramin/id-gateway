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
	// CheckAuthRateLimit checks if an auth request is allowed.
	// Takes the identifier (email/username) and IP for composite rate limiting.
	// Returns rate limit result with allowed status and retry-after info.
	CheckAuthRateLimit(ctx context.Context, identifier, ip string) (*AuthRateLimitResult, error)

	// RecordAuthFailure records a failed authentication attempt.
	// Used for progressive lockout per PRD-017 FR-2b.
	RecordAuthFailure(ctx context.Context, identifier, ip string) (*AuthLockoutState, error)

	// ClearAuthFailures clears auth failure state after successful login.
	ClearAuthFailures(ctx context.Context, identifier, ip string) error
}

// AuthRateLimitResult is the port model for rate limit check results.
// This is auth's view of the rate limit result - only fields auth needs.
type AuthRateLimitResult struct {
	Allowed    bool
	Remaining  int
	RetryAfter int // seconds until retry is allowed
	ResetAt    time.Time
}

// AuthLockoutState is the port model for auth lockout state.
// Used to communicate lockout info back to the handler.
type AuthLockoutState struct {
	FailureCount    int
	LockedUntil     *time.Time
	RequiresCaptcha bool
}
