package models

import (
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
)

// Purpose labels why data is processed. Purpose binding allows selective
// revocation without affecting other flows.
type Purpose = id.ConsentPurpose

// Supported consent purposes
// These should align with the purposes defined in the PRD and system design.
const (
	PurposeLogin         Purpose = id.ConsentPurposeLogin
	PurposeRegistryCheck Purpose = id.ConsentPurposeRegistryCheck
	PurposeVCIssuance    Purpose = id.ConsentPurposeVCIssuance
	PurposeDecision      Purpose = id.ConsentPurposeDecision
)

// ParsePurpose creates a Purpose from a string, validating it against the allowed set.
// Returns error if the purpose is empty or not in the supported set.
func ParsePurpose(s string) (Purpose, error) {
	return id.ParseConsentPurpose(s)
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

// RecordFilter allows filtering consent records by purpose and status.
type RecordFilter struct {
	Purpose *Purpose
	Status  *Status
}
