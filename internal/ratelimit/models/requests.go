package models

import "time"

// AddAllowlistRequest is the API request for adding an allowlist entry.
// Per PRD-017 FR-4: POST /admin/rate-limit/allowlist
type AddAllowlistRequest struct {
	Type       AllowlistEntryType `json:"type" validate:"required,oneof=ip user_id"`
	Identifier string             `json:"identifier" validate:"required"`
	Reason     string             `json:"reason" validate:"required"`
	ExpiresAt  *time.Time         `json:"expires_at,omitempty"`
}

// Validate validates the AddAllowlistRequest fields.
// API input rules - not domain invariants.
func (r *AddAllowlistRequest) Validate() error {
	// TODO: Implement validation
	// - Type must be "ip" or "user_id"
	// - Identifier must be non-empty
	// - If Type is "ip", validate IP format
	// - If Type is "user_id", validate UUID format
	// - Reason must be non-empty
	// - ExpiresAt if provided must be in the future
	return nil
}

// RemoveAllowlistRequest is the API request for removing an allowlist entry.
type RemoveAllowlistRequest struct {
	Type       AllowlistEntryType `json:"type" validate:"required,oneof=ip user_id"`
	Identifier string             `json:"identifier" validate:"required"`
}

// Validate validates the RemoveAllowlistRequest fields.
func (r *RemoveAllowlistRequest) Validate() error {
	// TODO: Implement validation
	return nil
}

// ResetRateLimitRequest is the API request for resetting a rate limit counter.
// Admin operation per PRD-017 TR-1.
type ResetRateLimitRequest struct {
	Type       AllowlistEntryType `json:"type" validate:"required,oneof=ip user_id"`
	Identifier string             `json:"identifier" validate:"required"`
	Class      EndpointClass      `json:"class,omitempty"` // optional, reset specific class
}

// Validate validates the ResetRateLimitRequest fields.
func (r *ResetRateLimitRequest) Validate() error {
	// TODO: Implement validation
	return nil
}
