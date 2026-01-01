// Package shared provides the shared kernel for the VC bounded context.
//
// The shared kernel contains domain primitives that are used across the VC context.
// These types form the common vocabulary for verifiable credentials.
//
// Domain Purity: This package contains only pure domain types with no I/O,
// no context.Context, and no time.Now() calls. Time is always received as
// a parameter from the application layer.
package shared

import (
	"errors"
	"time"
)

// IssuedAt represents the timestamp when a credential was issued.
// This is a value object that encapsulates issuance timing.
type IssuedAt struct {
	value time.Time
}

// ErrInvalidIssuedAt indicates the issued_at time is invalid.
var ErrInvalidIssuedAt = errors.New("issued_at cannot be zero")

// NewIssuedAt creates an IssuedAt from a time value.
// The time should be provided by the application layer (not called with time.Now() in domain).
func NewIssuedAt(t time.Time) (IssuedAt, error) {
	if t.IsZero() {
		return IssuedAt{}, ErrInvalidIssuedAt
	}
	return IssuedAt{value: t}, nil
}

// Time returns the underlying time value.
func (i IssuedAt) Time() time.Time {
	return i.value
}

// IsZero returns true if the issued_at time is zero.
func (i IssuedAt) IsZero() bool {
	return i.value.IsZero()
}

// ExpiresAt represents the timestamp when a credential expires.
// This is a value object that encapsulates expiration timing.
//
// Invariants:
//   - ExpiresAt must be after IssuedAt when both are present
//   - Zero value means no expiration (permanent credential)
type ExpiresAt struct {
	value time.Time
}

// ErrInvalidExpiresAt indicates the expires_at time is invalid.
var ErrInvalidExpiresAt = errors.New("expires_at cannot be zero")

// ErrExpiresBeforeIssued indicates expires_at is before issued_at.
var ErrExpiresBeforeIssued = errors.New("expires_at must be after issued_at")

// NewExpiresAt creates an ExpiresAt from a time value.
// The time should be provided by the application layer (not called with time.Now() in domain).
func NewExpiresAt(t time.Time) (ExpiresAt, error) {
	if t.IsZero() {
		return ExpiresAt{}, ErrInvalidExpiresAt
	}
	return ExpiresAt{value: t}, nil
}

// NewExpiresAtAfter creates an ExpiresAt that is validated to be after the given IssuedAt.
// This enforces the invariant that expiration must come after issuance.
func NewExpiresAtAfter(t time.Time, issuedAt IssuedAt) (ExpiresAt, error) {
	if t.IsZero() {
		return ExpiresAt{}, ErrInvalidExpiresAt
	}
	if !t.After(issuedAt.Time()) {
		return ExpiresAt{}, ErrExpiresBeforeIssued
	}
	return ExpiresAt{value: t}, nil
}

// NoExpiration returns an ExpiresAt with zero value, indicating no expiration.
// Used for permanent credentials (MVP behavior per PRD-004).
func NoExpiration() ExpiresAt {
	return ExpiresAt{}
}

// Time returns the underlying time value.
func (e ExpiresAt) Time() time.Time {
	return e.value
}

// IsZero returns true if no expiration is set (permanent credential).
func (e ExpiresAt) IsZero() bool {
	return e.value.IsZero()
}

// IsExpiredAt checks if this credential has expired relative to the given time.
// Returns false if no expiration is set (permanent credential).
func (e ExpiresAt) IsExpiredAt(now time.Time) bool {
	if e.IsZero() {
		return false // No expiration = never expires
	}
	return now.After(e.value)
}
