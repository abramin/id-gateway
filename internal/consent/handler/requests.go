package handler

import (
	"fmt"
	"strings"

	"credo/internal/consent/models"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/validation"
)

// GrantRequest specifies which purposes to grant consent for.
type GrantRequest struct {
	Purposes []string `json:"purposes"`
}

// Normalize applies business defaults and sanitizes inputs.
func (r *GrantRequest) Normalize() {
	if r == nil {
		return
	}
	r.Purposes = dedupePurposes(r.Purposes)
}

// Validate checks that the request is well-formed.
func (r *GrantRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}
	return validatePurposes(r.Purposes)
}

// ToPurposes converts validated request purposes into domain purposes.
func (r *GrantRequest) ToPurposes() ([]models.Purpose, error) {
	if r == nil {
		return nil, dErrors.New(dErrors.CodeBadRequest, "request is required")
	}
	return toDomainPurposes(r.Purposes)
}

// RevokeRequest specifies which purposes to revoke consent for.
type RevokeRequest struct {
	Purposes []string `json:"purposes"`
}

// Normalize applies business defaults and sanitizes inputs.
func (r *RevokeRequest) Normalize() {
	if r == nil {
		return
	}
	r.Purposes = dedupePurposes(r.Purposes)
}

// Validate checks that the request is well-formed.
func (r *RevokeRequest) Validate() error {
	if r == nil {
		return dErrors.New(dErrors.CodeBadRequest, "request is required")
	}
	return validatePurposes(r.Purposes)
}

// ToPurposes converts validated request purposes into domain purposes.
func (r *RevokeRequest) ToPurposes() ([]models.Purpose, error) {
	if r == nil {
		return nil, dErrors.New(dErrors.CodeBadRequest, "request is required")
	}
	return toDomainPurposes(r.Purposes)
}

// validatePurposes validates a list of purpose strings.
// Enforces size limits, required fields, and syntax validation.
func validatePurposes(purposes []string) error {
	// Phase 1: Size validation
	if len(purposes) > validation.MaxPurposes {
		return dErrors.New(dErrors.CodeValidation, fmt.Sprintf("too many purposes: max %d allowed", validation.MaxPurposes))
	}
	// Phase 2: Required fields
	if len(purposes) == 0 {
		return dErrors.New(dErrors.CodeValidation, "purposes are required")
	}
	// Phase 3: Syntax validation
	for _, p := range purposes {
		if p == "" {
			return dErrors.New(dErrors.CodeValidation, "invalid purpose: "+p)
		}
		if _, err := models.ParsePurpose(p); err != nil {
			return dErrors.New(dErrors.CodeValidation, "invalid purpose: "+p)
		}
	}
	return nil
}

func toDomainPurposes(purposes []string) ([]models.Purpose, error) {
	parsed := make([]models.Purpose, 0, len(purposes))
	for _, p := range purposes {
		purpose, err := models.ParsePurpose(p)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, purpose)
	}
	return parsed, nil
}

// dedupePurposes removes duplicate purposes while preserving order.
func dedupePurposes(purposes []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(purposes))
	for _, p := range purposes {
		normalized := strings.TrimSpace(p)
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return result
}
