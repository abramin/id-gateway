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
