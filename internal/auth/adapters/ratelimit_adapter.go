package adapters

import (
	"context"

	"credo/internal/auth/ports"
	"credo/internal/ratelimit/checker"
)

// RateLimitAdapter is an in-process adapter that implements ports.RateLimitPort
// by directly calling the ratelimit checker service. This maintains the hexagonal
// architecture boundaries while keeping everything in a single process.
// When splitting into microservices, this can be replaced with a gRPC adapter
// without changing the auth handler.
type RateLimitAdapter struct {
	checker *checker.Service
}

// NewRateLimitAdapter creates a new in-process ratelimit adapter.
func NewRateLimitAdapter(checkerSvc *checker.Service) ports.RateLimitPort {
	return &RateLimitAdapter{
		checker: checkerSvc,
	}
}

// CheckAuthRateLimit checks if an auth request is allowed.
func (a *RateLimitAdapter) CheckAuthRateLimit(ctx context.Context, identifier, ip string) (*ports.AuthRateLimitResult, error) {
	result, err := a.checker.CheckAuthRateLimit(ctx, identifier, ip)
	if err != nil {
		return nil, err
	}

	return &ports.AuthRateLimitResult{
		Allowed:    result.Allowed,
		Remaining:  result.Remaining,
		RetryAfter: result.RetryAfter,
		ResetAt:    result.ResetAt,
	}, nil
}

// RecordAuthFailure records a failed authentication attempt.
func (a *RateLimitAdapter) RecordAuthFailure(ctx context.Context, identifier, ip string) (*ports.AuthLockoutState, error) {
	lockout, err := a.checker.RecordAuthFailure(ctx, identifier, ip)
	if err != nil {
		return nil, err
	}

	return &ports.AuthLockoutState{
		FailureCount:    lockout.FailureCount,
		LockedUntil:     lockout.LockedUntil,
		RequiresCaptcha: lockout.RequiresCaptcha,
	}, nil
}

// ClearAuthFailures clears auth failure state after successful login.
func (a *RateLimitAdapter) ClearAuthFailures(ctx context.Context, identifier, ip string) error {
	return a.checker.ClearAuthFailures(ctx, identifier, ip)
}
