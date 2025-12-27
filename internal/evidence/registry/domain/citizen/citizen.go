// Package citizen defines the Citizen subdomain within the Registry bounded context.
//
// The Citizen subdomain handles identity verification through national population
// registries. It is responsible for:
//   - Validating citizen identity against authoritative sources
//   - Managing PII (Personally Identifiable Information) with GDPR compliance
//   - Providing minimization capabilities for regulated environments
//
// Domain Purity: This package contains only pure domain logic with no I/O,
// no context.Context, and no time.Now() calls.
//
// Aggregate: CitizenVerification is the aggregate root, protecting the invariants
// around identity data and its minimization state.
package citizen

import (
	"credo/internal/evidence/registry/domain/shared"
	id "credo/pkg/domain"
)

// PersonalDetails is a value object containing PII from the citizen registry.
// In regulated mode, these details are stripped during minimization.
//
// Invariants:
//   - FullName should be non-empty for valid records
//   - DateOfBirth should be in YYYY-MM-DD format
type PersonalDetails struct {
	FullName    string
	DateOfBirth string
	Address     string
}

// IsEmpty returns true if all personal details are empty (minimized state).
func (p PersonalDetails) IsEmpty() bool {
	return p.FullName == "" && p.DateOfBirth == "" && p.Address == ""
}

// VerificationStatus represents the outcome of a citizen registry lookup.
type VerificationStatus struct {
	Valid     bool
	CheckedAt shared.CheckedAt
}

// IsValid returns whether the citizen record is valid/active.
func (v VerificationStatus) IsValid() bool {
	return v.Valid
}

// CitizenVerification is the aggregate root for citizen identity verification.
//
// This aggregate encapsulates:
//   - The lookup key (NationalID from pkg/domain)
//   - Personal details (PII that can be minimized)
//   - Verification status (validity and timestamp)
//   - Evidence provenance (which provider, confidence level)
//
// Invariants:
//   - NationalID is always present and valid
//   - CheckedAt is always set
//   - Minimized records have empty PersonalDetails
type CitizenVerification struct {
	nationalID id.NationalID
	details    PersonalDetails
	status     VerificationStatus
	providerID shared.ProviderID
	confidence shared.Confidence
	minimized  bool
}

// NewCitizenVerification creates a new citizen verification record.
// This is the only way to construct a valid CitizenVerification.
func NewCitizenVerification(
	nationalID id.NationalID,
	details PersonalDetails,
	valid bool,
	checkedAt shared.CheckedAt,
	providerID shared.ProviderID,
	confidence shared.Confidence,
) CitizenVerification {
	return CitizenVerification{
		nationalID: nationalID,
		details:    details,
		status: VerificationStatus{
			Valid:     valid,
			CheckedAt: checkedAt,
		},
		providerID: providerID,
		confidence: confidence,
		minimized:  false,
	}
}

func (c CitizenVerification) NationalID() id.NationalID {
	return c.nationalID
}

func (c CitizenVerification) PersonalDetails() PersonalDetails {
	return c.details
}

func (c CitizenVerification) FullName() string {
	return c.details.FullName
}

func (c CitizenVerification) DateOfBirth() string {
	return c.details.DateOfBirth
}

func (c CitizenVerification) Address() string {
	return c.details.Address
}

func (c CitizenVerification) IsValid() bool {
	return c.status.Valid
}

func (c CitizenVerification) CheckedAt() shared.CheckedAt {
	return c.status.CheckedAt
}

func (c CitizenVerification) ProviderID() shared.ProviderID {
	return c.providerID
}

func (c CitizenVerification) Confidence() shared.Confidence {
	return c.confidence
}

func (c CitizenVerification) IsMinimized() bool {
	return c.minimized
}

// Minimized returns a new CitizenVerification with PII stripped.
// This is the GDPR-compliant representation for regulated environments.
//
// The returned value:
//   - Retains: NationalID, Valid status, CheckedAt, ProviderID, Confidence
//   - Strips: FullName, DateOfBirth, Address
//   - Is marked as minimized (IsMinimized returns true)
//
// This method is pure - it returns a new value without modifying the original.
func (c CitizenVerification) Minimized() CitizenVerification {
	return CitizenVerification{
		nationalID: c.nationalID,
		details:    PersonalDetails{}, // Empty - PII stripped
		status:     c.status,
		providerID: c.providerID,
		confidence: c.confidence,
		minimized:  true,
	}
}

// WithoutNationalID returns a minimized version that also clears the national ID.
// Use this for maximum data minimization where even the lookup key should be hidden.
func (c CitizenVerification) WithoutNationalID() CitizenVerification {
	minimized := c.Minimized()
	minimized.nationalID = id.NationalID{} // Zero value
	return minimized
}
