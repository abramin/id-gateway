package models

import "time"

type RateLimitExceededResponse struct {
	Error      string `json:"error"` // "rate_limit_exceeded" or "user_rate_limit_exceeded"
	Message    string `json:"message"`
	RetryAfter int    `json:"retry_after"` // seconds
}

type UserRateLimitExceededResponse struct {
	Error          string    `json:"error"` // "user_rate_limit_exceeded"
	Message        string    `json:"message"`
	QuotaLimit     int       `json:"quota_limit"`
	QuotaRemaining int       `json:"quota_remaining"`
	QuotaReset     time.Time `json:"quota_reset"`
}

type AllowlistEntryResponse struct {
	Allowlisted bool       `json:"allowlisted"`
	Identifier  string     `json:"identifier"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

type QuotaResponse struct {
	QuotaLimit     int       `json:"quota_limit"`
	QuotaRemaining int       `json:"quota_remaining"`
	QuotaReset     time.Time `json:"quota_reset"`
}

type ServiceOverloadedResponse struct {
	Error      string `json:"error"`   // "service_unavailable"
	Message    string `json:"message"` // "Service is temporarily overloaded..."
	RetryAfter int    `json:"retry_after"`
}

// AuthLockoutResponse is returned when an account is temporarily locked
// due to too many failed authentication attempts (PRD-017 FR-2b).
type AuthLockoutResponse struct {
	Error      string `json:"error"`       // "account_locked"
	Message    string `json:"message"`     // User-friendly lockout message
	RetryAfter int    `json:"retry_after"` // seconds until lockout expires
	SupportURL string `json:"support_url"` // URL for user support
}

// ClientRateLimitExceededResponse is returned when an OAuth client exceeds
// its rate limit quota (PRD-017 FR-2c).
type ClientRateLimitExceededResponse struct {
	Error      string `json:"error"`       // "client_rate_limit_exceeded"
	Message    string `json:"message"`     // User-friendly message
	RetryAfter int    `json:"retry_after"` // seconds until limit resets
}
