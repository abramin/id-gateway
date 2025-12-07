package models

import (
	"time"

	pkgerrors "id-gateway/pkg/domain-errors"
)

// ConsentPurpose labels why data is processed. Purpose binding allows selective
// revocation without affecting other flows.
type ConsentPurpose string

type GrantConsentRequest struct {
	Purposes []ConsentPurpose `json:"purposes" validate:"required,min=1,dive,oneof=login registry_check vc_issuance decision_evaluation"`
}

// response := map[string]any{
// 	"granted": formatConsentResponses(granted, time.Now()),
// 	"message": formatActionMessage("Consent granted for %d purposes", len(granted)),
// }

type ConsentActionResponse struct {
	Granted []ConsentGrant `json:"granted"`
	Message string         `json:"message,omitempty"`
}

type ConsentGrant struct {
	Purpose   ConsentPurpose `json:"purpose" validate:"required,oneof=login registry_check vc_issuance decision_evaluation"`
	GrantedAt time.Time      `json:"granted_at" validate:"required"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty" validate:"omitempty"`
	Status    string         `json:"status"` // "active" for new grant
}

// RevokeConsentRequest specifies which purposes to revoke.
type RevokeConsentRequest struct {
	Purposes []ConsentPurpose `json:"purposes" validate:"required,min=1,dive,oneof=login registry_check vc_issuance decision_evaluation"`
}

const (
	ConsentPurposeLogin         ConsentPurpose = "login"
	ConsentPurposeRegistryCheck ConsentPurpose = "registry_check"
	ConsentPurposeVCIssuance    ConsentPurpose = "vc_issuance"
	ConsentPurposeDecision      ConsentPurpose = "decision_evaluation"
)

// ValidConsentPurposes is the single source of truth for all valid consent purposes.
var ValidConsentPurposes = map[ConsentPurpose]bool{
	ConsentPurposeLogin:         true,
	ConsentPurposeRegistryCheck: true,
	ConsentPurposeVCIssuance:    true,
	ConsentPurposeDecision:      true,
}

// ConsentRecord captures a user's decision for a specific purpose.
type ConsentRecord struct {
	ID        string         `json:"id"`
	UserID    string         `json:"user_id"`
	Purpose   ConsentPurpose `json:"purpose"`
	GrantedAt time.Time      `json:"granted_at"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
	RevokedAt *time.Time     `json:"revoked_at,omitempty"`
}

// IsActive returns true when consent is currently valid.
func (c ConsentRecord) IsActive(now time.Time) bool {
	if c.RevokedAt != nil {
		return false
	}
	if c.ExpiresAt != nil && c.ExpiresAt.Before(now) {
		return false
	}
	return true
}

// Status reports the consent lifecycle state at the provided time.
func (c ConsentRecord) Status(now time.Time) string {
	if c.RevokedAt != nil {
		return "revoked"
	}
	if c.ExpiresAt != nil && c.ExpiresAt.Before(now) {
		return "expired"
	}
	return "active"
}

// EnsureConsent enforces that consent exists and is active for the given purpose.
func EnsureConsent(consents []*ConsentRecord, purpose ConsentPurpose, now time.Time) error {
	for _, c := range consents {
		if c.Purpose == purpose && c.IsActive(now) {
			return nil
		}
	}
	return pkgerrors.New(pkgerrors.CodeMissingConsent, "consent not granted for required purpose")
}

// IsValid checks if the consent purpose is one of the supported enum values.
func (cp ConsentPurpose) IsValid() bool {
	return ValidConsentPurposes[cp]
}
