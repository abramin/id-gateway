package adapters

import (
	"context"
	"time"

	"credo/internal/auth/ports"
)

// EndpointClass identifies the type of endpoint for rate limiting purposes.
// Defined locally to avoid coupling to internal/ratelimit/models.
// Exported so composition root can create wrappers returning this type.
type EndpointClass string

// ClassAuth is the endpoint class for auth operations.
const ClassAuth EndpointClass = "auth"

// AuthCheckResult is the local contract type for auth lockout check results.
// Maps to ratelimit's AuthRateLimitResult without importing it.
// Exported so composition root can create wrappers returning this type.
type AuthCheckResult struct {
	Allowed    bool
	Remaining  int
	RetryAfter int
	ResetAt    time.Time
}

// AuthLockoutResult is the local contract type for lockout state after recording failure.
// Maps to ratelimit's AuthLockout without importing it.
// Exported so composition root can create wrappers returning this type.
type AuthLockoutResult struct {
	FailureCount    int
	LockedUntil     *time.Time
	RequiresCaptcha bool
}

// IPCheckResult is the local contract type for IP rate limit check results.
// Maps to ratelimit's RateLimitResult without importing it.
// Exported so composition root can create wrappers returning this type.
type IPCheckResult struct {
	Allowed    bool
	Remaining  int
	RetryAfter int
	ResetAt    time.Time
}

// AuthLockoutChecker defines the interface for auth lockout operations.
// Defined locally to avoid coupling to ratelimit service packages.
type AuthLockoutChecker interface {
	Check(ctx context.Context, identifier, ip string) (*AuthCheckResult, error)
	RecordFailure(ctx context.Context, identifier, ip string) (*AuthLockoutResult, error)
	Clear(ctx context.Context, identifier, ip string) error
}

// RequestLimiter defines the interface for request rate limiting.
// Defined locally to avoid coupling to ratelimit service packages.
type RequestLimiter interface {
	CheckIP(ctx context.Context, ip string, class EndpointClass) (*IPCheckResult, error)
}

// RateLimitAdapter is an in-process adapter that implements ports.RateLimitPort
// by directly calling the ratelimit services. This maintains the hexagonal
// architecture boundaries while keeping everything in a single process.
// When splitting into microservices, this can be replaced with a gRPC adapter
// without changing the auth handler.
type RateLimitAdapter struct {
	authLockout AuthLockoutChecker
	requests    RequestLimiter
}

// New builds an in-process adapter backed by ratelimit services.
func New(authLockout AuthLockoutChecker, requests RequestLimiter) ports.RateLimitPort {
	return &RateLimitAdapter{
		authLockout: authLockout,
		requests:    requests,
	}
}

func (a *RateLimitAdapter) CheckAuthRateLimit(ctx context.Context, identifier, ip string) (*ports.AuthRateLimitResult, error) {
	// Check auth lockout first (brute force protection)
	authResult, err := a.authLockout.Check(ctx, identifier, ip)
	if err != nil {
		return nil, err
	}
	if !authResult.Allowed {
		return &ports.AuthRateLimitResult{
			Allowed:    false,
			Remaining:  authResult.Remaining,
			RetryAfter: authResult.RetryAfter,
			ResetAt:    authResult.ResetAt,
		}, nil
	}

	// Secondary defense: IP rate limit for auth endpoints
	ipResult, err := a.requests.CheckIP(ctx, ip, ClassAuth)
	if err != nil {
		return nil, err
	}
	if !ipResult.Allowed {
		return &ports.AuthRateLimitResult{
			Allowed:    false,
			Remaining:  ipResult.Remaining,
			RetryAfter: ipResult.RetryAfter,
			ResetAt:    ipResult.ResetAt,
		}, nil
	}

	// Both checks passed - return combined result with IP limit info
	return &ports.AuthRateLimitResult{
		Allowed:    true,
		Remaining:  ipResult.Remaining,
		RetryAfter: 0,
		ResetAt:    ipResult.ResetAt,
	}, nil
}

func (a *RateLimitAdapter) RecordAuthFailure(ctx context.Context, identifier, ip string) (*ports.AuthLockoutState, error) {
	lockout, err := a.authLockout.RecordFailure(ctx, identifier, ip)
	if err != nil {
		return nil, err
	}

	return &ports.AuthLockoutState{
		FailureCount:    lockout.FailureCount,
		LockedUntil:     lockout.LockedUntil,
		RequiresCaptcha: lockout.RequiresCaptcha,
	}, nil
}

func (a *RateLimitAdapter) ClearAuthFailures(ctx context.Context, identifier, ip string) error {
	return a.authLockout.Clear(ctx, identifier, ip)
}
