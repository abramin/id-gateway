package config

import (
	"time"

	"credo/internal/ratelimit/models"
)

type Config struct {
	IPLimits    map[models.EndpointClass]Limit
	UserLimits  map[models.EndpointClass]Limit
	Global      GlobalLimit
	AuthLockout AuthLockoutConfig
	QuotaTiers  map[models.QuotaTier]QuotaLimit
}

type Limit struct {
	RequestsPerWindow int
	Window            time.Duration
}

type GlobalLimit struct {
	PerInstancePerSecond int // 1000 req/sec per instance
	GlobalPerSecond      int // 10000 req/sec across all instances
}

type AuthLockoutConfig struct {
	AttemptsPerWindow      int           // 5 attempts per 15 min
	WindowDuration         time.Duration // 15 minutes
	HardLockThreshold      int           // 10 failures/day triggers hard lock
	HardLockDuration       time.Duration // 15 minutes
	CaptchaAfterLockouts   int           // 3 consecutive lockouts require CAPTCHA
	ProgressiveBackoffBase time.Duration // 250ms base delay
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
		},
		UserLimits: map[models.EndpointClass]Limit{
			models.ClassAuth:      {RequestsPerWindow: 50, Window: time.Hour},  // Consent operations
			models.ClassSensitive: {RequestsPerWindow: 20, Window: time.Hour},  // VC issuance
			models.ClassRead:      {RequestsPerWindow: 200, Window: time.Hour}, // Decision evaluations
			models.ClassWrite:     {RequestsPerWindow: 100, Window: time.Hour}, // Registry lookups
		},
		Global: GlobalLimit{
			PerInstancePerSecond: 1000,
			GlobalPerSecond:      10000,
		},
		AuthLockout: AuthLockoutConfig{
			AttemptsPerWindow:      5,
			WindowDuration:         15 * time.Minute,
			HardLockThreshold:      10,
			HardLockDuration:       15 * time.Minute,
			CaptchaAfterLockouts:   3,
			ProgressiveBackoffBase: 250 * time.Millisecond,
		},
		QuotaTiers: map[models.QuotaTier]QuotaLimit{
			models.QuotaTierFree:       {MonthlyRequests: 1000, OverageAllowed: false},
			models.QuotaTierStarter:    {MonthlyRequests: 10000, OverageAllowed: true, OverageRate: 0.01},
			models.QuotaTierBusiness:   {MonthlyRequests: 100000, OverageAllowed: true, OverageRate: 0.005},
			models.QuotaTierEnterprise: {MonthlyRequests: -1, OverageAllowed: true}, // unlimited
		},
	}
}

func (c *Config) GetIPLimit(class models.EndpointClass) (requestsPerWindow int, window time.Duration) {
	if limit, ok := c.IPLimits[class]; ok {
		return limit.RequestsPerWindow, limit.Window
	}
	// Default to read limits if class not found
	return c.IPLimits[models.ClassRead].RequestsPerWindow, c.IPLimits[models.ClassRead].Window
}

func (c *Config) GetUserLimit(class models.EndpointClass) (requestsPerWindow int, window time.Duration) {
	if limit, ok := c.UserLimits[class]; ok {
		return limit.RequestsPerWindow, limit.Window
	}
	// Default to read limits if class not found
	return c.UserLimits[models.ClassRead].RequestsPerWindow, c.UserLimits[models.ClassRead].Window
}
