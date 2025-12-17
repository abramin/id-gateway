package service

import (
	"time"

	"credo/internal/ratelimit/models"
)

// Config holds rate limiting configuration.
// Per PRD-017 TR-4: Rate limit configuration.
type Config struct {
	// Per-IP rate limits by endpoint class
	// Per PRD-017 FR-1: IP rate limit tiers
	IPLimits map[models.EndpointClass]Limit

	// Per-user rate limits by endpoint class
	// Per PRD-017 FR-2: User rate limit tiers
	UserLimits map[models.EndpointClass]Limit

	// Global limits for DDoS protection
	// Per PRD-017 FR-6: Global throttling
	Global GlobalLimit

	// Auth-specific lockout configuration
	// Per PRD-017 FR-2b: OWASP authentication protections
	AuthLockout AuthLockoutConfig

	// Partner quota tiers
	// Per PRD-017 FR-5: API key quotas
	QuotaTiers map[models.QuotaTier]QuotaLimit
}

// Limit defines rate limit parameters for an endpoint class.
type Limit struct {
	RequestsPerWindow int
	Window            time.Duration
}

// GlobalLimit defines global throttling parameters.
// Per PRD-017 FR-6: Per-instance and global limits.
type GlobalLimit struct {
	PerInstancePerSecond int // 1000 req/sec per instance
	GlobalPerSecond      int // 10000 req/sec across all instances
}

// AuthLockoutConfig defines authentication lockout parameters.
// Per PRD-017 FR-2b: OWASP authentication-specific throttling.
type AuthLockoutConfig struct {
	AttemptsPerWindow      int           // 5 attempts per 15 min
	WindowDuration         time.Duration // 15 minutes
	HardLockThreshold      int           // 10 failures/day triggers hard lock
	HardLockDuration       time.Duration // 15 minutes
	CaptchaAfterLockouts   int           // 3 consecutive lockouts require CAPTCHA
	ProgressiveBackoffBase time.Duration // 250ms base delay
}

// QuotaLimit defines monthly quota parameters for a tier.
type QuotaLimit struct {
	MonthlyRequests int
	OverageAllowed  bool
	OverageRate     float64 // cost per request over limit
}

// DefaultConfig returns sensible defaults per PRD-017.
func DefaultConfig() *Config {
	return &Config{
		// Per PRD-017 FR-1: IP rate limits
		IPLimits: map[models.EndpointClass]Limit{
			models.ClassAuth:      {RequestsPerWindow: 10, Window: time.Minute},
			models.ClassSensitive: {RequestsPerWindow: 30, Window: time.Minute},
			models.ClassRead:      {RequestsPerWindow: 100, Window: time.Minute},
			models.ClassWrite:     {RequestsPerWindow: 50, Window: time.Minute},
		},
		// Per PRD-017 FR-2: User rate limits
		UserLimits: map[models.EndpointClass]Limit{
			models.ClassAuth:      {RequestsPerWindow: 50, Window: time.Hour},  // Consent operations
			models.ClassSensitive: {RequestsPerWindow: 20, Window: time.Hour},  // VC issuance
			models.ClassRead:      {RequestsPerWindow: 200, Window: time.Hour}, // Decision evaluations
			models.ClassWrite:     {RequestsPerWindow: 100, Window: time.Hour}, // Registry lookups
		},
		// Per PRD-017 FR-6: Global limits
		Global: GlobalLimit{
			PerInstancePerSecond: 1000,
			GlobalPerSecond:      10000,
		},
		// Per PRD-017 FR-2b: Auth lockout config
		AuthLockout: AuthLockoutConfig{
			AttemptsPerWindow:      5,
			WindowDuration:         15 * time.Minute,
			HardLockThreshold:      10,
			HardLockDuration:       15 * time.Minute,
			CaptchaAfterLockouts:   3,
			ProgressiveBackoffBase: 250 * time.Millisecond,
		},
		// Per PRD-017 FR-5: Quota tiers
		QuotaTiers: map[models.QuotaTier]QuotaLimit{
			models.QuotaTierFree:       {MonthlyRequests: 1000, OverageAllowed: false},
			models.QuotaTierStarter:    {MonthlyRequests: 10000, OverageAllowed: true, OverageRate: 0.01},
			models.QuotaTierBusiness:   {MonthlyRequests: 100000, OverageAllowed: true, OverageRate: 0.005},
			models.QuotaTierEnterprise: {MonthlyRequests: -1, OverageAllowed: true}, // unlimited
		},
	}
}

// GetIPLimit returns the IP rate limit for an endpoint class.
func (c *Config) GetIPLimit(class models.EndpointClass) (int, time.Duration) {
	if limit, ok := c.IPLimits[class]; ok {
		return limit.RequestsPerWindow, limit.Window
	}
	// Default to read limits if class not found
	return c.IPLimits[models.ClassRead].RequestsPerWindow, c.IPLimits[models.ClassRead].Window
}

// GetUserLimit returns the user rate limit for an endpoint class.
func (c *Config) GetUserLimit(class models.EndpointClass) (int, time.Duration) {
	if limit, ok := c.UserLimits[class]; ok {
		return limit.RequestsPerWindow, limit.Window
	}
	// Default to read limits if class not found
	return c.UserLimits[models.ClassRead].RequestsPerWindow, c.UserLimits[models.ClassRead].Window
}
