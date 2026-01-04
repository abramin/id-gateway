// Package models defines domain types for the ratelimit module.
//
// Key concepts:
//   - EndpointClass: Categorizes endpoints by sensitivity for rate limit configuration
//   - RateLimitResult: Outcome of a rate limit check (allowed/denied, remaining quota)
//   - AuthLockout: Tracks authentication failures to prevent brute-force attacks
//   - AllowlistEntry: Exempts specific IPs or users from rate limiting
//   - APIKeyQuota: Monthly usage tracking for partner API keys
package models

import (
	"net"
	"time"

	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
)

// EndpointClass categorizes API endpoints by sensitivity level for rate limiting.
// Each class has different per-IP and per-user limits configured in config.Config.
// Used by middleware to apply appropriate rate limits to incoming requests.
type EndpointClass string

const (
	// ClassAuth: Authentication endpoints (10 req/min) - /auth/authorize, /auth/token
	ClassAuth EndpointClass = "auth"
	// ClassSensitive: Sensitive operations (30 req/min) - /consent, /vc/issue, /decision/evaluate
	ClassSensitive EndpointClass = "sensitive"
	// ClassRead: Read operations (100 req/min) - /auth/userinfo, /consent, /me/data-export
	ClassRead EndpointClass = "read"
	// ClassWrite: Write operations (50 req/min) - general mutations
	ClassWrite EndpointClass = "write"
	// ClassAdmin: Admin server endpoints (10 req/min) - strict limit to prevent brute-force
	ClassAdmin EndpointClass = "admin"
)

// IsValid returns true if the endpoint class is a recognized value.
func (c EndpointClass) IsValid() bool {
	switch c {
	case ClassAuth, ClassSensitive, ClassRead, ClassWrite, ClassAdmin:
		return true
	}
	return false
}

// AllowlistEntryType identifies whether an allowlist entry exempts an IP address or user.
type AllowlistEntryType string

const (
	AllowlistTypeIP     AllowlistEntryType = "ip"      // Exempts a specific IP address
	AllowlistTypeUserID AllowlistEntryType = "user_id" // Exempts a specific user
)

// ParseAllowlistEntryType validates and converts a string to AllowlistEntryType.
// Returns an error if the string is empty or not a valid type.
func ParseAllowlistEntryType(s string) (AllowlistEntryType, error) {
	if s == "" {
		return "", dErrors.New(dErrors.CodeInvalidInput, "allowlist entry type cannot be empty")
	}
	t := AllowlistEntryType(s)
	if !t.IsValid() {
		return "", dErrors.New(dErrors.CodeInvalidInput, "invalid allowlist entry type: must be 'ip' or 'user_id'")
	}
	return t, nil
}

func (t AllowlistEntryType) IsValid() bool {
	return t == AllowlistTypeIP || t == AllowlistTypeUserID
}

func (t AllowlistEntryType) String() string {
	return string(t)
}

// AllowlistIdentifier is a validated identifier for allowlist entries.
// The validation depends on the allowlist entry type.
type AllowlistIdentifier string

func (i AllowlistIdentifier) String() string {
	return string(i)
}

// ParseAllowlistIdentifier validates and converts an identifier for the given entry type.
func ParseAllowlistIdentifier(entryType AllowlistEntryType, identifier string) (AllowlistIdentifier, error) {
	if identifier == "" {
		return "", dErrors.New(dErrors.CodeInvalidInput, "identifier cannot be empty")
	}
	if !entryType.IsValid() {
		return "", dErrors.New(dErrors.CodeInvalidInput, "invalid allowlist entry type")
	}
	switch entryType {
	case AllowlistTypeIP:
		if net.ParseIP(identifier) == nil {
			return "", dErrors.New(dErrors.CodeInvalidInput, "identifier must be a valid IP address")
		}
	case AllowlistTypeUserID:
		if _, err := id.ParseUserID(identifier); err != nil {
			return "", dErrors.New(dErrors.CodeInvalidInput, "identifier must be a valid user_id")
		}
	}
	return AllowlistIdentifier(identifier), nil
}

// RateLimitResult is the outcome of a rate limit check.
// Returned by BucketStore.Allow and service Check methods.
//
// Fields:
//   - Allowed: true if the request should proceed, false if rate limited
//   - Bypassed: true if an allowlist entry exempted this request from checking
//   - Limit: maximum requests allowed in the window
//   - Remaining: requests left before hitting the limit
//   - ResetAt: when the current window expires and counters reset
//   - RetryAfter: seconds to wait before retrying (only set when Allowed=false)
type RateLimitResult struct {
	Allowed    bool      `json:"allowed"`
	Bypassed   bool      `json:"bypassed,omitempty"`
	Limit      int       `json:"limit"`
	Remaining  int       `json:"remaining"`
	ResetAt    time.Time `json:"reset_at"`
	RetryAfter int       `json:"retry_after,omitempty"`
}

// AuthRateLimitResult extends RateLimitResult with authentication-specific fields.
// Returned by authlockout.Service.Check for login/password-reset endpoints.
//
// Additional fields:
//   - RequiresCaptcha: true after 3 consecutive lockouts in 24 hours (FR-2b)
//   - FailureCount: number of failed attempts in the current window
type AuthRateLimitResult struct {
	RateLimitResult
	RequiresCaptcha bool `json:"requires_captcha"`
	FailureCount    int  `json:"failure_count"`
}

// AllowlistEntry exempts an IP address or user from rate limiting.
// Created by admins via the admin API, with optional expiration.
// Checked by services before applying rate limits.
type AllowlistEntry struct {
	ID         string              `json:"id"`
	Type       AllowlistEntryType  `json:"type"`
	Identifier AllowlistIdentifier `json:"identifier"` // IP address or user_id
	Reason     string              `json:"reason"`     // Admin-provided justification
	ExpiresAt  *time.Time          `json:"expires_at,omitempty"`
	CreatedAt  time.Time           `json:"created_at"`
	CreatedBy  id.UserID           `json:"created_by"` // Admin who created the entry
}

// RateLimitViolation is an audit record created when a request is rate limited.
// Used for security monitoring and abuse detection.
type RateLimitViolation struct {
	ID            string        `json:"id"`
	Identifier    string        `json:"identifier"` // IP or user_id that was limited
	EndpointClass EndpointClass `json:"endpoint_class"`
	Endpoint      string        `json:"endpoint"`       // The specific endpoint path
	Limit         int           `json:"limit"`          // The limit that was exceeded
	WindowSeconds int           `json:"window_seconds"` // The window duration
	OccurredAt    time.Time     `json:"occurred_at"`
}

// QuotaTier represents subscription levels for partner API keys.
// Higher tiers have larger monthly request quotas.
type QuotaTier string

const (
	QuotaTierFree       QuotaTier = "free"       // 1,000 requests/month
	QuotaTierStarter    QuotaTier = "starter"    // 10,000 requests/month
	QuotaTierBusiness   QuotaTier = "business"   // 100,000 requests/month
	QuotaTierEnterprise QuotaTier = "enterprise" // 1,000,000 requests/month
)

// IsValid returns true if the tier is a recognized value.
func (t QuotaTier) IsValid() bool {
	switch t {
	case QuotaTierFree, QuotaTierStarter, QuotaTierBusiness, QuotaTierEnterprise:
		return true
	}
	return false
}

// APIKeyQuota tracks monthly usage for a partner API key.
// Quotas reset on the first day of each month.
// Used by quota.Service to enforce monthly limits and track overage.
type APIKeyQuota struct {
	APIKeyID       id.APIKeyID `json:"api_key_id"`
	Tier           QuotaTier   `json:"tier"`
	MonthlyLimit   int         `json:"monthly_limit"`   // Max requests allowed this month
	CurrentUsage   int         `json:"current_usage"`   // Requests used so far
	OverageAllowed bool        `json:"overage_allowed"` // If true, requests proceed over quota (billed)
	PeriodStart    time.Time   `json:"period_start"`    // First day of current month
	PeriodEnd      time.Time   `json:"period_end"`      // Last moment of current month
}

// AuthLockout tracks authentication failures to prevent brute-force attacks (PRD-017 FR-2b).
//
// Behavior:
//   - After 5 failures in 15 minutes: soft lock (sliding window)
//   - After 10 daily failures: hard lock for 15 minutes
//   - After 3 consecutive lockouts in 24 hours: require CAPTCHA
//
// The Identifier is a composite key of username/email + IP address,
// preventing cross-IP attacks while allowing legitimate multi-device access.
type AuthLockout struct {
	Identifier      string     `json:"identifier"`             // Composite key: "username:IP"
	FailureCount    int        `json:"failure_count"`          // Failures in current 15-min window
	DailyFailures   int        `json:"daily_failures"`         // Failures today (for hard lock threshold)
	LockedUntil     *time.Time `json:"locked_until,omitempty"` // Hard lock expiration
	LastFailureAt   time.Time  `json:"last_failure_at"`
	RequiresCaptcha bool       `json:"requires_captcha"` // Set after 3 consecutive lockouts
}

// BackoffPolicy is a value object that encapsulates progressive backoff calculation.
type BackoffPolicy struct {
	Base           time.Duration // Base delay (e.g., 250ms)
	Cap            time.Duration // Maximum delay cap (e.g., 1s)
	WindowDuration time.Duration // Duration of the sliding window
}

// NewBackoffPolicy creates a backoff policy with the given parameters.
// Returns a zero-value policy if base is zero (no backoff).
func NewBackoffPolicy(base, cap, windowDuration time.Duration) BackoffPolicy {
	return BackoffPolicy{
		Base:           base,
		Cap:            cap,
		WindowDuration: windowDuration,
	}
}

// DefaultBackoffPolicy returns the standard auth lockout backoff policy.
// Implements exponential backoff: 250ms → 500ms → 1s (capped).
func DefaultBackoffPolicy() BackoffPolicy {
	return BackoffPolicy{
		Base:           250 * time.Millisecond,
		Cap:            time.Second,
		WindowDuration: 15 * time.Minute,
	}
}

// CalculateBackoff returns the progressive backoff delay for the given failure count.
// This is a pure function - it receives failureCount and returns the computed delay.
// Implements exponential backoff: base → 2*base → 4*base... capped at Cap.
func (p BackoffPolicy) CalculateBackoff(failureCount int) time.Duration {
	if failureCount <= 0 || p.Base == 0 {
		return 0
	}
	// Exponential backoff with cap
	delay := p.Base * time.Duration(1<<(failureCount-1))
	if delay > p.Cap {
		return p.Cap
	}
	return delay
}

// ResetTime returns when the lockout window will reset based on last failure time.
// This is a pure function - it receives lastFailureAt and returns the computed reset time.
func (p BackoffPolicy) ResetTime(lastFailureAt time.Time) time.Time {
	return lastFailureAt.Add(p.WindowDuration)
}

// NewAllowlistEntry creates a validated allowlist entry.
// The id parameter should be generated by the caller (e.g., uuid.NewString()) to keep the domain pure.
// Returns an error if id, type, identifier, or reason is invalid/empty.
func NewAllowlistEntry(id string, entryType AllowlistEntryType, identifier, reason string, createdBy id.UserID, expiresAt *time.Time, now time.Time) (*AllowlistEntry, error) {
	if id == "" {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "id cannot be empty")
	}
	if !entryType.IsValid() {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "invalid allowlist entry type")
	}
	if reason == "" {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "reason cannot be empty")
	}
	parsedIdentifier, err := ParseAllowlistIdentifier(entryType, identifier)
	if err != nil {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, err.Error())
	}

	return &AllowlistEntry{
		ID:         id,
		Type:       entryType,
		Identifier: parsedIdentifier,
		Reason:     reason,
		ExpiresAt:  expiresAt,
		CreatedAt:  now,
		CreatedBy:  createdBy,
	}, nil
}

// IsExpired checks if the entry has expired using the current wall-clock time.
// IMPURE: Calls time.Now() internally. Use IsExpiredAt for pure/testable code.
func (e *AllowlistEntry) IsExpired() bool {
	return e.IsExpiredAt(time.Now())
}

// IsExpiredAt checks if the entry has expired at the given time.
// PURE: Receives time as parameter, returns computed result.
func (e *AllowlistEntry) IsExpiredAt(now time.Time) bool {
	if e.ExpiresAt == nil {
		return false
	}
	return now.After(*e.ExpiresAt)
}

// NewAuthLockout creates a new lockout record for an identifier.
// The identifier should be a composite key created by NewAuthLockoutKey.
func NewAuthLockout(identifier string, now time.Time) (*AuthLockout, error) {
	if identifier == "" {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "identifier cannot be empty")
	}
	return &AuthLockout{
		Identifier:      identifier,
		FailureCount:    0,
		DailyFailures:   0,
		LockedUntil:     nil,
		LastFailureAt:   now,
		RequiresCaptcha: false,
	}, nil
}

// IsLocked checks if the lockout is active using the current wall-clock time.
// IMPURE: Calls time.Now() internally. Use IsLockedAt for pure/testable code.
func (l *AuthLockout) IsLocked() bool {
	return l.IsLockedAt(time.Now())
}

// IsLockedAt checks if the lockout is active at the given time.
// PURE: Receives time as parameter, returns computed result.
func (l *AuthLockout) IsLockedAt(now time.Time) bool {
	if l.LockedUntil == nil {
		return false
	}
	return now.Before(*l.LockedUntil)
}

// RecordFailure increments failure counters and updates timestamp.
// Returns the updated lockout record for chaining.
func (l *AuthLockout) RecordFailure(now time.Time) *AuthLockout {
	l.FailureCount++
	l.DailyFailures++
	l.LastFailureAt = now
	return l
}

// ShouldHardLock returns true if failure count has reached the hard lock threshold.
func (l *AuthLockout) ShouldHardLock(threshold int) bool {
	return l.FailureCount >= threshold
}

// ApplyHardLock sets the lockout expiration time.
func (l *AuthLockout) ApplyHardLock(duration time.Duration, now time.Time) {
	lockedUntil := now.Add(duration)
	l.LockedUntil = &lockedUntil
}

// ShouldRequireCaptcha returns true if daily failures have reached the captcha threshold.
func (l *AuthLockout) ShouldRequireCaptcha(threshold int) bool {
	return l.DailyFailures >= threshold
}

// MarkRequiresCaptcha sets the captcha requirement flag.
func (l *AuthLockout) MarkRequiresCaptcha() {
	l.RequiresCaptcha = true
}

// Clear resets the lockout record to allow fresh attempts.
func (l *AuthLockout) Clear() {
	l.FailureCount = 0
	l.LockedUntil = nil
	// Note: DailyFailures and RequiresCaptcha are NOT cleared here
	// as they track 24-hour state, not per-window state
}

// RemainingAttempts returns how many attempts are left before hitting the limit.
func (l *AuthLockout) RemainingAttempts(limit int) int {
	remaining := limit - l.FailureCount
	if remaining < 0 {
		return 0
	}
	return remaining
}

// IsAttemptLimitReached returns true if the failure count has reached the window limit.
func (l *AuthLockout) IsAttemptLimitReached(limit int) bool {
	return l.FailureCount >= limit
}

// NewAPIKeyQuota creates a new quota record for an API key.
// Automatically sets period boundaries to the current calendar month.
func NewAPIKeyQuota(apiKeyID id.APIKeyID, tier QuotaTier, monthlyLimit int, overageAllowed bool, now time.Time) (*APIKeyQuota, error) {
	if apiKeyID.IsNil() {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "api_key_id cannot be empty")
	}
	if !tier.IsValid() {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "invalid quota tier")
	}
	if monthlyLimit < 0 {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "monthly_limit cannot be negative")
	}

	periodStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	periodEnd := periodStart.AddDate(0, 1, 0).Add(-time.Nanosecond)

	return &APIKeyQuota{
		APIKeyID:       apiKeyID,
		Tier:           tier,
		MonthlyLimit:   monthlyLimit,
		CurrentUsage:   0,
		OverageAllowed: overageAllowed,
		PeriodStart:    periodStart,
		PeriodEnd:      periodEnd,
	}, nil
}

// IsOverQuota returns true if current usage has reached or exceeded the monthly limit.
func (q *APIKeyQuota) IsOverQuota() bool {
	return q.CurrentUsage >= q.MonthlyLimit
}

// NewRateLimitViolation creates an audit record for a rate-limited request.
// The id parameter should be generated by the caller (e.g., uuid.NewString()) to keep the domain pure.
// Used for security monitoring to detect abuse patterns.
func NewRateLimitViolation(id, identifier string, class EndpointClass, endpoint string, limit, windowSeconds int, now time.Time) (*RateLimitViolation, error) {
	if id == "" {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "id cannot be empty")
	}
	if identifier == "" {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "identifier cannot be empty")
	}
	if !class.IsValid() {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "invalid endpoint class")
	}
	if endpoint == "" {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "endpoint cannot be empty")
	}
	if limit <= 0 {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "limit must be positive")
	}
	if windowSeconds <= 0 {
		return nil, dErrors.New(dErrors.CodeInvariantViolation, "window_seconds must be positive")
	}

	return &RateLimitViolation{
		ID:            id,
		Identifier:    identifier,
		EndpointClass: class,
		Endpoint:      endpoint,
		Limit:         limit,
		WindowSeconds: windowSeconds,
		OccurredAt:    now,
	}, nil
}
