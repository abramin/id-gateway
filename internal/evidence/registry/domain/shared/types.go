// Package shared provides the shared kernel for the Registry bounded context.
//
// The shared kernel contains domain primitives that are used across both the
// Citizen and Sanctions subdomains. These types form the common vocabulary
// for identity evidence within the Registry context.
//
// Note: NationalID is defined in pkg/domain to avoid duplication. This package
// provides evidence-specific types (Confidence, CheckedAt, ProviderID).
//
// Domain Purity: This package contains only pure domain types with no I/O,
// no context.Context, and no time.Now() calls. Time is always received as
// a parameter from the application layer.
package shared

import (
	"errors"
	"time"
)

// Confidence represents the reliability score of evidence from a provider.
// Range: 0.0 (no confidence) to 1.0 (authoritative source).
//
// Invariants:
//   - Value must be between 0.0 and 1.0 inclusive
type Confidence struct {
	value float64
}

// ErrInvalidConfidence indicates the confidence score is out of range.
var ErrInvalidConfidence = errors.New("invalid confidence: must be between 0.0 and 1.0")

// NewConfidence creates a validated Confidence score.
func NewConfidence(value float64) (Confidence, error) {
	if value < 0.0 || value > 1.0 {
		return Confidence{}, ErrInvalidConfidence
	}
	return Confidence{value: value}, nil
}

// MustConfidence creates a Confidence, panicking if invalid.
func MustConfidence(value float64) Confidence {
	c, err := NewConfidence(value)
	if err != nil {
		panic(err)
	}
	return c
}

// Authoritative returns a Confidence of 1.0 (fully trusted source).
func Authoritative() Confidence {
	return Confidence{value: 1.0}
}

func (c Confidence) Value() float64 {
	return c.value
}

func (c Confidence) IsAuthoritative() bool {
	return c.value == 1.0
}

// CheckedAt represents the timestamp when evidence was fetched from a registry.
// This is a value object that encapsulates verification timing.
type CheckedAt struct {
	value time.Time
}

// NewCheckedAt creates a CheckedAt from a time value.
// The time should be provided by the application layer (not called with time.Now() in domain).
func NewCheckedAt(t time.Time) CheckedAt {
	return CheckedAt{value: t}
}

func (c CheckedAt) Time() time.Time {
	return c.value
}

// IsExpiredAt checks if this check is older than the given TTL relative to 'now'.
// Both 'now' and 'ttl' are provided by the caller to maintain domain purity.
func (c CheckedAt) IsExpiredAt(now time.Time, ttl time.Duration) bool {
	return now.Sub(c.value) > ttl
}

// IsFreshAt checks if this check is still valid given the TTL and current time.
func (c CheckedAt) IsFreshAt(now time.Time, ttl time.Duration) bool {
	return !c.IsExpiredAt(now, ttl)
}

func (c CheckedAt) IsZero() bool {
	return c.value.IsZero()
}

// ProviderID identifies the source of evidence.
// This is used to track which registry or provider produced a piece of evidence.
type ProviderID struct {
	value string
}

// NewProviderID creates a ProviderID.
func NewProviderID(value string) ProviderID {
	return ProviderID{value: value}
}

func (p ProviderID) String() string {
	return p.value
}

func (p ProviderID) IsZero() bool {
	return p.value == ""
}
