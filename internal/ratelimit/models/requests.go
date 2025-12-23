package models

import (
	"net"
	"strings"
	"time"

	dErrors "credo/pkg/domain-errors"
)

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

// Follows validation order: Size -> Required -> Syntax -> Semantic.
func (r *AddAllowlistRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}

	if len(r.Identifier) > 255 {
		return dErrors.New(dErrors.CodeValidation, "identifier must be 255 characters or less")
	}
	if len(r.Reason) > 500 {
		return dErrors.New(dErrors.CodeValidation, "reason must be 500 characters or less")
	}

	if r.Type == "" {
		return dErrors.New(dErrors.CodeValidation, "type is required")
	}
	if r.Identifier == "" {
		return dErrors.New(dErrors.CodeValidation, "identifier is required")
	}
	if r.Reason == "" {
		return dErrors.New(dErrors.CodeValidation, "reason is required")
	}

	entryType := AllowlistEntryType(r.Type)
	if !entryType.IsValid() {
		return dErrors.New(dErrors.CodeValidation, "type must be 'ip' or 'user_id'")
	}

	// Semantic: validate IP format when type is 'ip'
	if entryType == AllowlistTypeIP {
		if net.ParseIP(r.Identifier) == nil {
			return dErrors.New(dErrors.CodeValidation, "identifier must be a valid IP address")
		}
	}

	if r.ExpiresAt != nil && r.ExpiresAt.Before(time.Now()) {
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

	if len(r.Identifier) > 255 {
		return dErrors.New(dErrors.CodeValidation, "identifier must be 255 characters or less")
	}

	if r.Type == "" {
		return dErrors.New(dErrors.CodeValidation, "type is required")
	}
	if r.Identifier == "" {
		return dErrors.New(dErrors.CodeValidation, "identifier is required")
	}

	entryType := AllowlistEntryType(r.Type)
	if !entryType.IsValid() {
		return dErrors.New(dErrors.CodeValidation, "type must be 'ip' or 'user_id'")
	}

	// Semantic: validate IP format when type is 'ip'
	if entryType == AllowlistTypeIP {
		if net.ParseIP(r.Identifier) == nil {
			return dErrors.New(dErrors.CodeValidation, "identifier must be a valid IP address")
		}
	}

	return nil
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

	if len(r.Identifier) > 255 {
		return dErrors.New(dErrors.CodeValidation, "identifier must be 255 characters or less")
	}

	if r.Type == "" {
		return dErrors.New(dErrors.CodeValidation, "type is required")
	}
	if r.Identifier == "" {
		return dErrors.New(dErrors.CodeValidation, "identifier is required")
	}

	if !r.Type.IsValid() {
		return dErrors.New(dErrors.CodeValidation, "type must be 'ip' or 'user_id'")
	}

	// Semantic: validate IP format when type is 'ip'
	if r.Type == AllowlistTypeIP {
		if net.ParseIP(r.Identifier) == nil {
			return dErrors.New(dErrors.CodeValidation, "identifier must be a valid IP address")
		}
	}

	if r.Class != "" {
		if !r.Class.IsValid() {
			return dErrors.New(dErrors.CodeValidation, "class must be 'auth', 'sensitive', 'read', or 'write'")
		}
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

func (r *UpdateQuotaTierRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}
	tier := QuotaTier(strings.TrimSpace(strings.ToLower(r.Tier)))
	if !tier.IsValid() {
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
