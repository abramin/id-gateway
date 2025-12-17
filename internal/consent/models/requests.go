package models

import (
	"fmt"

	"credo/internal/sentinel"
)

// GrantRequest specifies which purposes to grant consent for.
type GrantRequest struct {
	Purposes []Purpose `json:"purposes"`
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
		return fmt.Errorf("request is required: %w", sentinel.ErrBadRequest)
	}
	if len(r.Purposes) == 0 {
		return fmt.Errorf("purposes are required: %w", sentinel.ErrInvalidInput)
	}
	for _, p := range r.Purposes {
		if !p.IsValid() {
			return fmt.Errorf("invalid purpose %q: %w", p, sentinel.ErrInvalidInput)
		}
	}
	return nil
}

// RevokeRequest specifies which purposes to revoke consent for.
type RevokeRequest struct {
	Purposes []Purpose `json:"purposes"`
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
		return fmt.Errorf("request is required: %w", sentinel.ErrBadRequest)
	}
	if len(r.Purposes) == 0 {
		return fmt.Errorf("purposes are required: %w", sentinel.ErrInvalidInput)
	}
	for _, p := range r.Purposes {
		if !p.IsValid() {
			return fmt.Errorf("invalid purpose %q: %w", p, sentinel.ErrInvalidInput)
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
