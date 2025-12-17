package models

import "time"

// RateLimitExceededResponse is the API response when rate limit is exceeded.
// Per PRD-017 FR-1: 429 response format.
type RateLimitExceededResponse struct {
	Error      string `json:"error"`       // "rate_limit_exceeded" or "user_rate_limit_exceeded"
	Message    string `json:"message"`
	RetryAfter int    `json:"retry_after"` // seconds
}

// UserRateLimitExceededResponse is the API response when user quota is exceeded.
// Per PRD-017 FR-2: User-specific rate limit response.
type UserRateLimitExceededResponse struct {
	Error          string    `json:"error"` // "user_rate_limit_exceeded"
	Message        string    `json:"message"`
	QuotaLimit     int       `json:"quota_limit"`
	QuotaRemaining int       `json:"quota_remaining"`
	QuotaReset     time.Time `json:"quota_reset"`
}

// AllowlistEntryResponse is the API response for allowlist operations.
// Per PRD-017 FR-4: Response for allowlist add.
type AllowlistEntryResponse struct {
	Allowlisted bool       `json:"allowlisted"`
	Identifier  string     `json:"identifier"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// QuotaResponse is the API response with quota headers info.
// Per PRD-017 FR-5: X-Quota-* headers.
type QuotaResponse struct {
	QuotaLimit     int       `json:"quota_limit"`
	QuotaRemaining int       `json:"quota_remaining"`
	QuotaReset     time.Time `json:"quota_reset"`
}

// ServiceOverloadedResponse is the API response when global throttle is hit.
// Per PRD-017 FR-6: 503 response for DDoS protection.
type ServiceOverloadedResponse struct {
	Error      string `json:"error"`   // "service_unavailable"
	Message    string `json:"message"` // "Service is temporarily overloaded..."
	RetryAfter int    `json:"retry_after"`
}
