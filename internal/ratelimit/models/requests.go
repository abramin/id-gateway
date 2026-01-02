package models

import (
	"net"
	"strings"
	"time"

	dErrors "credo/pkg/domain-errors"
)

// validateAllowlistEntry validates common fields for allowlist and rate limit requests.
// Follows validation order: Size -> Required -> Syntax -> Semantic.
func validateAllowlistEntry(entryType AllowlistEntryType, identifier string) error {
	// Size
	if len(identifier) > 255 {
		return dErrors.New(dErrors.CodeValidation, "identifier must be 255 characters or less")
	}

	// Required
	if entryType == "" {
		return dErrors.New(dErrors.CodeValidation, "type is required")
	}
	if identifier == "" {
		return dErrors.New(dErrors.CodeValidation, "identifier is required")
	}

	// Syntax
	if !entryType.IsValid() {
		return dErrors.New(dErrors.CodeValidation, "type must be 'ip' or 'user_id'")
	}

	// Semantic: validate IP format when type is 'ip'
	if entryType == AllowlistTypeIP {
		if net.ParseIP(identifier) == nil {
			return dErrors.New(dErrors.CodeValidation, "identifier must be a valid IP address")
		}
	}

	return nil
}

type AddAllowlistRequest struct {
	Type       AllowlistEntryType `json:"type"`
	Identifier string             `json:"identifier"`
	Reason     string             `json:"reason"`
	ExpiresAt  *time.Time         `json:"expires_at,omitempty"`
}

func (r *AddAllowlistRequest) Normalize() {
	if r == nil {
		return
	}
	r.Type = AllowlistEntryType(strings.TrimSpace(strings.ToLower(string(r.Type))))
	r.Identifier = strings.TrimSpace(r.Identifier)
	r.Reason = strings.TrimSpace(r.Reason)
}

// Validate validates the request using wall-clock time for expiration check.
// Follows validation order: Size -> Required -> Syntax -> Semantic.
func (r *AddAllowlistRequest) Validate() error {
	return r.ValidateAt(time.Now())
}

// ValidateAt validates the request using the provided time for expiration check.
// This pure version enables testability. Follows validation order: Size -> Required -> Syntax -> Semantic.
func (r *AddAllowlistRequest) ValidateAt(now time.Time) error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}

	// Validate common entry fields
	if err := validateAllowlistEntry(r.Type, r.Identifier); err != nil {
		return err
	}

	// AddAllowlist-specific validations
	if len(r.Reason) > 500 {
		return dErrors.New(dErrors.CodeValidation, "reason must be 500 characters or less")
	}
	if r.Reason == "" {
		return dErrors.New(dErrors.CodeValidation, "reason is required")
	}
	if r.ExpiresAt != nil && r.ExpiresAt.Before(now) {
		return dErrors.New(dErrors.CodeValidation, "expires_at must be in the future")
	}

	return nil
}

type RemoveAllowlistRequest struct {
	Type       AllowlistEntryType `json:"type"`
	Identifier string             `json:"identifier"`
}

func (r *RemoveAllowlistRequest) Normalize() {
	if r == nil {
		return
	}
	r.Type = AllowlistEntryType(strings.TrimSpace(strings.ToLower(string(r.Type))))
	r.Identifier = strings.TrimSpace(r.Identifier)
}

// Follows validation order: Size -> Required -> Syntax -> Semantic.
func (r *RemoveAllowlistRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}
	return validateAllowlistEntry(r.Type, r.Identifier)
}

type ResetRateLimitRequest struct {
	Type       AllowlistEntryType `json:"type"`
	Identifier string             `json:"identifier"`
	Class      EndpointClass      `json:"class,omitempty"` // optional: specific endpoint class to reset
}

func (r *ResetRateLimitRequest) Normalize() {
	if r == nil {
		return
	}
	r.Type = AllowlistEntryType(strings.TrimSpace(strings.ToLower(string(r.Type))))
	r.Identifier = strings.TrimSpace(r.Identifier)
	r.Class = EndpointClass(strings.TrimSpace(strings.ToLower(string(r.Class))))
}

// Follows validation order: Size -> Required -> Syntax -> Semantic.
func (r *ResetRateLimitRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}

	// Validate common entry fields
	if err := validateAllowlistEntry(r.Type, r.Identifier); err != nil {
		return err
	}

	// ResetRateLimit-specific: optional class validation
	if r.Class != "" && !r.Class.IsValid() {
		return dErrors.New(dErrors.CodeValidation, "class must be 'auth', 'sensitive', 'read', or 'write'")
	}

	return nil
}

// =============================================================================
// PRD-017 FR-5: Partner API Quota Requests/Responses
// =============================================================================

// ResetQuotaRequest is the request body for POST /admin/rate-limit/quota/:api_key/reset
type ResetQuotaRequest struct {
	Reason string `json:"reason,omitempty"`
}

// UpdateQuotaTierRequest is the request body for PUT /admin/rate-limit/quota/:api_key/tier
type UpdateQuotaTierRequest struct {
	Tier string `json:"tier"`
}

func (r *UpdateQuotaTierRequest) Normalize() {
	if r == nil {
		return
	}
	r.Tier = strings.TrimSpace(strings.ToLower(r.Tier))
}

func (r *UpdateQuotaTierRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}
	if !QuotaTier(r.Tier).IsValid() {
		return dErrors.New(dErrors.CodeValidation, "tier must be 'free', 'starter', 'business', or 'enterprise'")
	}
	return nil
}

// QuotaUsageResponse is the response for GET /admin/rate-limit/quota/:api_key
type QuotaUsageResponse struct {
	APIKeyID  string    `json:"api_key_id"`
	Tier      string    `json:"tier"`
	Usage     int       `json:"usage"`
	Limit     int       `json:"limit"`
	Remaining int       `json:"remaining"`
	ResetAt   time.Time `json:"reset_at"`
}
