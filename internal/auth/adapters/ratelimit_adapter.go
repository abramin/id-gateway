package adapters

import (
	"context"

	"credo/internal/auth/ports"
	ratelimitModels "credo/internal/ratelimit/models"
)

// classAuth is a local constant for the auth endpoint class.
// Defined here to avoid coupling to internal/ratelimit/models.
const classAuth ratelimitModels.EndpointClass = "auth"

// authLockoutChecker defines the interface for auth lockout operations.
// Defined locally to avoid coupling to ratelimit service packages.
type authLockoutChecker interface {
	Check(ctx context.Context, identifier, ip string) (*ratelimitModels.AuthRateLimitResult, error)
	RecordFailure(ctx context.Context, identifier, ip string) (*ratelimitModels.AuthLockout, error)
	Clear(ctx context.Context, identifier, ip string) error
}

// requestLimiter defines the interface for request rate limiting.
// Defined locally to avoid coupling to ratelimit service packages.
type requestLimiter interface {
	CheckIP(ctx context.Context, ip string, class ratelimitModels.EndpointClass) (*ratelimitModels.RateLimitResult, error)
}

// RateLimitAdapter is an in-process adapter that implements ports.RateLimitPort
// by directly calling the ratelimit services. This maintains the hexagonal
// architecture boundaries while keeping everything in a single process.
// When splitting into microservices, this can be replaced with a gRPC adapter
// without changing the auth handler.
type RateLimitAdapter struct {
	authLockout authLockoutChecker
	requests    requestLimiter
}

// New builds an in-process adapter backed by ratelimit services.
func New(authLockout authLockoutChecker, requests requestLimiter) ports.RateLimitPort {
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
	ipResult, err := a.requests.CheckIP(ctx, ip, classAuth)
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
