package models

import (
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
)

// Purpose labels why data is processed. Purpose binding allows selective
// revocation without affecting other flows.
type Purpose string

// Supported consent purposes
// These should align with the purposes defined in the PRD and system design.
const (
	PurposeLogin         Purpose = "login"
	PurposeRegistryCheck Purpose = "registry_check"
	PurposeVCIssuance    Purpose = "vc_issuance"
	PurposeDecision      Purpose = "decision_evaluation"
)

// validPurposes is the single source of truth for all valid consent purposes.
var validPurposes = map[Purpose]bool{
	PurposeLogin:         true,
	PurposeRegistryCheck: true,
	PurposeVCIssuance:    true,
	PurposeDecision:      true,
}

// ParsePurpose creates a Purpose from a string, validating it against the allowed set.
// Returns error if the purpose is empty or not in validPurposes.
func ParsePurpose(s string) (Purpose, error) {
	if s == "" {
		return "", dErrors.New(dErrors.CodeInvalidInput, "purpose cannot be empty")
	}
	p := Purpose(s)
	if !p.IsValid() {
		return "", dErrors.New(dErrors.CodeInvalidInput, "invalid purpose")
	}
	return p, nil
}

// IsValid checks if the consent purpose is one of the supported enum values.
func (p Purpose) IsValid() bool {
	return validPurposes[p]
}

// String returns the string representation of the purpose.
func (p Purpose) String() string {
	return string(p)
}

// Status represents the lifecycle state of a consent record.
type Status string

const (
	StatusActive  Status = "active"
	StatusExpired Status = "expired"
	StatusRevoked Status = "revoked"
)

// ParseStatus creates a Status from a string, validating it against the allowed set.
// Returns error if the status is empty or not supported.
func ParseStatus(s string) (Status, error) {
	if s == "" {
		return "", dErrors.New(dErrors.CodeInvalidInput, "status cannot be empty")
	}
	status := Status(s)
	if !status.IsValid() {
		return "", dErrors.New(dErrors.CodeInvalidInput, "invalid status")
	}
	return status, nil
}

// IsValid checks if the status is one of the supported enum values.
func (s Status) IsValid() bool {
	return s == StatusActive || s == StatusExpired || s == StatusRevoked
}

// ConsentCheckState represents the outcome state of a consent check operation.
// This differs from Status in that it includes "missing" for when no consent exists.
type ConsentCheckState string

const (
	ConsentCheckStateMissing ConsentCheckState = "missing"
	ConsentCheckStateRevoked ConsentCheckState = "revoked"
	ConsentCheckStateExpired ConsentCheckState = "expired"
	ConsentCheckStateActive  ConsentCheckState = "active"
)

// String returns the string representation of the consent check state.
func (c ConsentCheckState) String() string {
	return string(c)
}

// ConsentScope identifies a consent aggregate by user and purpose.
// It is the stable boundary for read/write operations on consent records.
type ConsentScope struct {
	UserID  id.UserID
	Purpose Purpose
}

// NewConsentScope constructs a validated ConsentScope.
func NewConsentScope(userID id.UserID, purpose Purpose) (ConsentScope, error) {
	if userID.IsNil() {
		return ConsentScope{}, dErrors.New(dErrors.CodeInvariantViolation, "user ID required")
	}
	if !purpose.IsValid() {
		return ConsentScope{}, dErrors.New(dErrors.CodeInvariantViolation, "invalid consent purpose")
	}
	return ConsentScope{UserID: userID, Purpose: purpose}, nil
}
