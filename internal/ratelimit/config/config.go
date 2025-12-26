package config

import (
	"time"

	"credo/internal/ratelimit/models"
)

type Config struct {
	IPLimits     map[models.EndpointClass]Limit
	UserLimits   map[models.EndpointClass]Limit
	ClientLimits ClientLimitConfig // Per-client rate limits (PRD-017 FR-2c)
	Global       GlobalLimit
	AuthLockout  AuthLockoutConfig
	QuotaTiers   map[models.QuotaTier]QuotaLimit
}

// ClientLimitConfig defines per-client rate limits based on client type (PRD-017 FR-2c).
type ClientLimitConfig struct {
	ConfidentialLimit Limit // Server-side clients with secure secret storage
	PublicLimit       Limit // SPAs/mobile apps - higher abuse risk
}

type Limit struct {
	RequestsPerWindow int
	Window            time.Duration
}

type GlobalLimit struct {
	PerInstancePerSecond int // 1000 req/sec per instance
	GlobalPerSecond      int // 10000 req/sec across all instances
	PerInstancePerHour   int // 100000 req/hour per instance (PRD-017 FR-6)
}

type AuthLockoutConfig struct {
	AttemptsPerWindow      int           // 5 attempts per 15 min
	WindowDuration         time.Duration // 15 minutes
	HardLockThreshold      int           // 10 failures/day triggers hard lock
	HardLockDuration       time.Duration // 15 minutes
	CaptchaAfterLockouts   int           // 3 consecutive lockouts require CAPTCHA
	ProgressiveBackoffBase time.Duration // 250ms base delay
	SupportURL             string        // URL for user support (included in lockout response)
}

// CalculateBackoff returns the progressive backoff delay for the given failure count.
// Implements exponential backoff: 250ms → 500ms → 1s (capped).
func (c *AuthLockoutConfig) CalculateBackoff(failureCount int) time.Duration {
	if failureCount <= 0 {
		return 0
	}
	base := c.ProgressiveBackoffBase
	if base == 0 {
		base = 250 * time.Millisecond
	}
	// Exponential backoff with cap at 1 second
	delay := base * time.Duration(1<<(failureCount-1))
	if delay > time.Second {
		return time.Second
	}
	return delay
}

// ResetTime returns when the lockout window will reset based on last failure time.
func (c *AuthLockoutConfig) ResetTime(lastFailureAt time.Time) time.Time {
	return lastFailureAt.Add(c.WindowDuration)
}

type QuotaLimit struct {
	MonthlyRequests int
	OverageAllowed  bool
	OverageRate     float64 // cost per request over limit
}

func DefaultConfig() *Config {
	return &Config{
		IPLimits: map[models.EndpointClass]Limit{
			models.ClassAuth:      {RequestsPerWindow: 10, Window: time.Minute},
			models.ClassSensitive: {RequestsPerWindow: 30, Window: time.Minute},
			models.ClassRead:      {RequestsPerWindow: 100, Window: time.Minute},
			models.ClassWrite:     {RequestsPerWindow: 50, Window: time.Minute},
			models.ClassAdmin:     {RequestsPerWindow: 10, Window: time.Minute}, // Strict limit for admin server
		},
		UserLimits: map[models.EndpointClass]Limit{
			models.ClassAuth:      {RequestsPerWindow: 50, Window: time.Hour},  // Consent operations
			models.ClassSensitive: {RequestsPerWindow: 20, Window: time.Hour},  // VC issuance
			models.ClassRead:      {RequestsPerWindow: 200, Window: time.Hour}, // Decision evaluations
			models.ClassWrite:     {RequestsPerWindow: 100, Window: time.Hour}, // Registry lookups
			models.ClassAdmin:     {RequestsPerWindow: 20, Window: time.Hour},  // Admin operations
		},
		// Per-client rate limits (PRD-017 FR-2c)
		ClientLimits: ClientLimitConfig{
			ConfidentialLimit: Limit{RequestsPerWindow: 100, Window: time.Minute}, // Server-side clients
			PublicLimit:       Limit{RequestsPerWindow: 30, Window: time.Minute},  // SPAs/mobile apps
		},
		Global: GlobalLimit{
			PerInstancePerSecond: 1000,
			GlobalPerSecond:      10000,
			PerInstancePerHour:   100000, // PRD-017 FR-6
		},
		AuthLockout: AuthLockoutConfig{
			AttemptsPerWindow:      5,
			WindowDuration:         15 * time.Minute,
			HardLockThreshold:      10,
			HardLockDuration:       15 * time.Minute,
			CaptchaAfterLockouts:   3,
			ProgressiveBackoffBase: 250 * time.Millisecond,
			SupportURL:             "/support", // Override with actual support URL in production
		},
		QuotaTiers: map[models.QuotaTier]QuotaLimit{
			models.QuotaTierFree:       {MonthlyRequests: 1000, OverageAllowed: false},
			models.QuotaTierStarter:    {MonthlyRequests: 10000, OverageAllowed: true, OverageRate: 0.01},
			models.QuotaTierBusiness:   {MonthlyRequests: 100000, OverageAllowed: true, OverageRate: 0.005},
			models.QuotaTierEnterprise: {MonthlyRequests: -1, OverageAllowed: true}, // unlimited
		},
	}
}

// GetIPLimit returns the IP rate limit for the given endpoint class.
// Returns ok=false if no limit is configured (caller should deny the request per PRD-017 FR-1).
func (c *Config) GetIPLimit(class models.EndpointClass) (requestsPerWindow int, window time.Duration, ok bool) {
	if limit, found := c.IPLimits[class]; found {
		return limit.RequestsPerWindow, limit.Window, true
	}
	// Default-deny: return false if class not found (PRD-017 FR-1)
	return 0, 0, false
}

// GetUserLimit returns the user rate limit for the given endpoint class.
// Returns ok=false if no limit is configured (caller should deny the request per PRD-017 FR-1).
func (c *Config) GetUserLimit(class models.EndpointClass) (requestsPerWindow int, window time.Duration, ok bool) {
	if limit, found := c.UserLimits[class]; found {
		return limit.RequestsPerWindow, limit.Window, true
	}
	// Default-deny: return false if class not found (PRD-017 FR-1)
	return 0, 0, false
}
