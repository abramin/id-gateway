package models

import (
	"fmt"

	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/validation"
)

// ConsentRequest is the interface for consent request types that can be prepared for processing.
type ConsentRequest interface {
	Sanitize()
	Normalize()
	Validate() error
}

// GrantRequest specifies which purposes to grant consent for.
type GrantRequest struct {
	Purposes []Purpose `json:"purposes"`
}

// Sanitize is a no-op for GrantRequest since Purpose is an enum that shouldn't be modified.
func (r *GrantRequest) Sanitize() {
	// Purpose values are domain primitives (enums) - do not trim/modify
}

// Normalize applies business defaults and sanitizes inputs.
func (r *GrantRequest) Normalize() {
	if r == nil {
		return
	}
	// Deduplicate purposes
	r.Purposes = dedupePurposes(r.Purposes)
}

// Validate checks that the request is well-formed.
func (r *GrantRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}
	// Phase 1: Size validation
	if len(r.Purposes) > validation.MaxPurposes {
		return dErrors.New(dErrors.CodeValidation, fmt.Sprintf("too many purposes: max %d allowed", validation.MaxPurposes))
	}
	// Phase 2: Required fields
	if len(r.Purposes) == 0 {
		return dErrors.New(dErrors.CodeValidation, "purposes are required")
	}
	// Phase 3: Syntax validation
	for _, p := range r.Purposes {
		if !p.IsValid() {
			return dErrors.New(dErrors.CodeValidation, "invalid purpose: "+string(p))
		}
	}
	return nil
}

// RevokeRequest specifies which purposes to revoke consent for.
type RevokeRequest struct {
	Purposes []Purpose `json:"purposes"`
}

// Sanitize is a no-op for RevokeRequest since Purpose is an enum that shouldn't be modified.
func (r *RevokeRequest) Sanitize() {
	// Purpose values are domain primitives (enums) - do not trim/modify
}

// Normalize applies business defaults and sanitizes inputs.
func (r *RevokeRequest) Normalize() {
	if r == nil {
		return
	}
	// Deduplicate purposes
	r.Purposes = dedupePurposes(r.Purposes)
}

// Validate checks that the request is well-formed.
func (r *RevokeRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}
	// Phase 1: Size validation
	if len(r.Purposes) > validation.MaxPurposes {
		return dErrors.New(dErrors.CodeValidation, fmt.Sprintf("too many purposes: max %d allowed", validation.MaxPurposes))
	}
	// Phase 2: Required fields
	if len(r.Purposes) == 0 {
		return dErrors.New(dErrors.CodeValidation, "purposes are required")
	}
	// Phase 3: Syntax validation
	for _, p := range r.Purposes {
		if !p.IsValid() {
			return dErrors.New(dErrors.CodeValidation, "invalid purpose: "+string(p))
		}
	}
	return nil
}

// dedupePurposes removes duplicate purposes while preserving order.
func dedupePurposes(purposes []Purpose) []Purpose {
	seen := make(map[Purpose]struct{})
	result := make([]Purpose, 0, len(purposes))
	for _, p := range purposes {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			result = append(result, p)
		}
	}
	return result
}
