package main

import (
	"context"

	"credo/internal/auth/ports"
	"credo/internal/ratelimit/models"
	"credo/internal/ratelimit/service/authlockout"
	"credo/internal/ratelimit/service/requestlimit"
)

// RateLimitAdapter implements ports.RateLimitPort by calling ratelimit services directly.
// This adapter lives in the composition root to keep the auth module decoupled from
// ratelimit internals. When splitting into microservices, replace with a gRPC adapter.
type RateLimitAdapter struct {
	authLockout *authlockout.Service
	requests    *requestlimit.Service
}

// NewRateLimitAdapter creates an adapter that implements auth's RateLimitPort.
func NewRateLimitAdapter(authLockout *authlockout.Service, requests *requestlimit.Service) ports.RateLimitPort {
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
	ipResult, err := a.requests.CheckIP(ctx, ip, models.ClassAuth)
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
