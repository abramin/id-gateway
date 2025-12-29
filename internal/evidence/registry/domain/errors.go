// Package domain contains shared domain errors for evidence registry aggregates.
package domain

import "errors"

// Validation errors for domain aggregates.
// These enforce invariants at construction time.
var (
	ErrMissingNationalID = errors.New("national_id is required")
	ErrMissingCheckedAt  = errors.New("checked_at is required")
	ErrMissingProviderID = errors.New("provider_id is required")
	ErrMissingSource     = errors.New("source is required")
)
