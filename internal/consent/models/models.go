package models

import (
	"time"

	pkgerrors "id-gateway/pkg/domain-errors"
)

// Purpose labels why data is processed. Purpose binding allows selective
// revocation without affecting other flows.
// Audit event actions
const (
	AuditActionConsentGranted     = "consent_granted"
	AuditActionConsentRevoked     = "consent_revoked"
	AuditActionConsentCheckPassed = "consent_check_passed"
	AuditActionConsentCheckFailed = "consent_check_failed"
)

// Audit event decisions
const (
	AuditDecisionGranted = "granted"
	AuditDecisionRevoked = "revoked"
	AuditDecisionDenied  = "denied"
)

// Audit event reasons
const (
	AuditReasonUserInitiated = "user_initiated"
)

type Purpose string

type GrantRequest struct {
	Purposes []Purpose `json:"purposes" validate:"required,min=1,dive,oneof=login registry_check vc_issuance decision_evaluation"`
}

type GrantResponse struct {
	Granted []Consent `json:"granted"`
}

type Consent struct {
	ID        string     `json:"id"`
	Purpose   Purpose    `json:"purpose"`
	GrantedAt time.Time  `json:"granted_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type ConsentWithStatus struct {
	Consent
	Status Status `json:"status"` // "active", "expired", "revoked"
}

type ActionResponse struct {
	Granted []Grant `json:"granted"`
	Message string  `json:"message,omitempty"`
}

type Grant struct {
	Purpose   Purpose    `json:"purpose" validate:"required,oneof=login registry_check vc_issuance decision_evaluation"`
	GrantedAt time.Time  `json:"granted_at" validate:"required"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" validate:"omitempty"`
	Status    Status     `json:"status" validate:"required,oneof=active expired revoked"` // "active" for new grant
}

// RevokeRequest specifies which purposes to revoke.
type RevokeRequest struct {
	Purposes []Purpose `json:"purposes" validate:"required,min=1,dive,oneof=login registry_check vc_issuance decision_evaluation"`
}

// RevokeResponse matches PRD-002 spec - only revoked records
type RevokeResponse struct {
	Revoked []*Consent `json:"revoked"`
}

// ListResponse matches PRD-002 spec - uses "consents" not "consent_records"
type ListResponse struct {
	Consents []*ConsentWithStatus `json:"consents"`
}

type Status string

const (
	StatusActive  Status = "active"
	StatusExpired Status = "expired"
	StatusRevoked Status = "revoked"
)

// RecordFilter allows filtering consent records by purpose and status.
type RecordFilter struct {
	Purpose string
	Status  string
}

const (
	PurposeLogin         Purpose = "login"
	PurposeRegistryCheck Purpose = "registry_check"
	PurposeVCIssuance    Purpose = "vc_issuance"
	PurposeDecision      Purpose = "decision_evaluation"
)

// ValidPurposes is the single source of truth for all valid consent purposes.
var ValidPurposes = map[Purpose]bool{
	PurposeLogin:         true,
	PurposeRegistryCheck: true,
	PurposeVCIssuance:    true,
	PurposeDecision:      true,
}

// Record captures a user's decision for a specific purpose.
type Record struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	Purpose   Purpose    `json:"purpose"`
	GrantedAt time.Time  `json:"granted_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// IsActive returns true when consent is currently valid.
func (c Record) IsActive(now time.Time) bool {
	if c.RevokedAt != nil {
		return false
	}
	if c.ExpiresAt != nil && c.ExpiresAt.Before(now) {
		return false
	}
	return true
}

// Status reports the consent lifecycle state at the provided time.
func (c Record) ComputeStatus(now time.Time) Status {
	if c.RevokedAt != nil {
		return StatusRevoked
	}
	if c.ExpiresAt != nil && c.ExpiresAt.Before(now) {
		return StatusExpired
	}
	return StatusActive
}

// Ensure enforces that consent exists and is active for the given purpose.
func Ensure(consents []*Record, purpose Purpose, now time.Time) error {
	for _, c := range consents {
		if c.Purpose == purpose && c.IsActive(now) {
			return nil
		}
	}
	return pkgerrors.New(pkgerrors.CodeMissingConsent, "consent not granted for required purpose")
}

// IsValid checks if the consent purpose is one of the supported enum values.
func (cp Purpose) IsValid() bool {
	return ValidPurposes[cp]
}

// TODO: not sure this is needed
func ToConsentDTO(r *Record) *Consent {
	return &Consent{
		ID:        r.ID,
		Purpose:   r.Purpose,
		GrantedAt: r.GrantedAt,
		ExpiresAt: r.ExpiresAt,
		RevokedAt: r.RevokedAt,
	}
}
