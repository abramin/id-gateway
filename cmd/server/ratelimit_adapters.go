package main

import (
	"context"

	authAdapters "credo/internal/auth/adapters"
	"credo/internal/ratelimit/models"
	"credo/internal/ratelimit/service/authlockout"
	"credo/internal/ratelimit/service/requestlimit"
)

// authLockoutWrapper adapts authlockout.Service to auth adapter's AuthLockoutChecker interface.
// This wrapper converts ratelimit types to auth adapter types at the composition root,
// keeping the auth module decoupled from ratelimit/models.
type authLockoutWrapper struct {
	svc *authlockout.Service
}

func (w *authLockoutWrapper) Check(ctx context.Context, identifier, ip string) (*authAdapters.AuthCheckResult, error) {
	result, err := w.svc.Check(ctx, identifier, ip)
	if err != nil {
		return nil, err
	}
	return &authAdapters.AuthCheckResult{
		Allowed:    result.Allowed,
		Remaining:  result.Remaining,
		RetryAfter: result.RetryAfter,
		ResetAt:    result.ResetAt,
	}, nil
}

func (w *authLockoutWrapper) RecordFailure(ctx context.Context, identifier, ip string) (*authAdapters.AuthLockoutResult, error) {
	result, err := w.svc.RecordFailure(ctx, identifier, ip)
	if err != nil {
		return nil, err
	}
	return &authAdapters.AuthLockoutResult{
		FailureCount:    result.FailureCount,
		LockedUntil:     result.LockedUntil,
		RequiresCaptcha: result.RequiresCaptcha,
	}, nil
}

func (w *authLockoutWrapper) Clear(ctx context.Context, identifier, ip string) error {
	return w.svc.Clear(ctx, identifier, ip)
}

// requestLimiterWrapper adapts requestlimit.Service to auth adapter's RequestLimiter interface.
// This wrapper converts ratelimit types to auth adapter types at the composition root.
type requestLimiterWrapper struct {
	svc *requestlimit.Service
}

func (w *requestLimiterWrapper) CheckIP(ctx context.Context, ip string, class authAdapters.EndpointClass) (*authAdapters.IPCheckResult, error) {
	result, err := w.svc.CheckIP(ctx, ip, models.EndpointClass(class))
	if err != nil {
		return nil, err
	}
	return &authAdapters.IPCheckResult{
		Allowed:    result.Allowed,
		Remaining:  result.Remaining,
		RetryAfter: result.RetryAfter,
		ResetAt:    result.ResetAt,
	}, nil
}
