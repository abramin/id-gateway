package decision

import (
	"time"

	registrycontracts "credo/contracts/registry"
	vccontracts "credo/contracts/vc"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
)

// DecisionOutcome enumerates the possible gateway decisions.
type DecisionOutcome string

const (
	DecisionPass               DecisionOutcome = "pass"
	DecisionPassWithConditions DecisionOutcome = "pass_with_conditions"
	DecisionFail               DecisionOutcome = "fail"
)

// DerivedIdentity holds non-PII attributes used in decision making.
type DerivedIdentity struct {
	// Derived fields only; no raw PII.
	PseudonymousID id.UserID
	IsOver18       bool
	CitizenValid   bool
}

// DecisionInput groups the signals considered by the decision engine. It avoids
// raw PII by requiring derived identity attributes.
type DecisionInput struct {
	Identity   DerivedIdentity
	Sanctions  registrycontracts.SanctionsRecord
	Credential map[string]interface{}
}

// IsSanctioned returns true if the subject is on a sanctions list.
func (di DecisionInput) IsSanctioned() bool { return di.Sanctions.Listed }

// IsCitizenValid returns true if the citizen verification passed.
func (di DecisionInput) IsCitizenValid() bool { return di.Identity.CitizenValid }

// IsOfLegalAge returns true if the subject is 18 or older.
func (di DecisionInput) IsOfLegalAge() bool { return di.Identity.IsOver18 }

// DerivedIdentityFromCitizen strips PII while producing attributes required for
// decisions in regulated mode. Time is injected for deterministic testing.
func DerivedIdentityFromCitizen(userID id.UserID, citizen registrycontracts.CitizenRecord, now time.Time) DerivedIdentity {
	isOver18 := deriveIsOver18(citizen.DateOfBirth, now)
	return DerivedIdentity{
		PseudonymousID: userID, // treat as pseudonymous identifier; avoid emails/names.
		IsOver18:       isOver18,
		CitizenValid:   citizen.Valid,
	}
}

func deriveIsOver18(dob string, now time.Time) bool {
	if dob == "" {
		return false
	}
	birthDate, err := time.Parse("2006-01-02", dob)
	if err != nil {
		return false
	}
	return id.IsOver18(birthDate, now)
}

// Purpose defines supported decision purposes.
type Purpose string

const (
	PurposeAgeVerification    Purpose = "age_verification"
	PurposeSanctionsScreening Purpose = "sanctions_screening"
)

// ParsePurpose validates and parses a purpose string.
//
// Usage: call at trust boundaries for external input.
//
// Errors: returns CodeBadRequest for unsupported purposes.
func ParsePurpose(s string) (Purpose, error) {
	switch Purpose(s) {
	case PurposeAgeVerification, PurposeSanctionsScreening:
		return Purpose(s), nil
	default:
		return "", dErrors.New(dErrors.CodeBadRequest, "unsupported purpose: must be age_verification or sanctions_screening")
	}
}

// DecisionReason encodes the reason for a decision.
type DecisionReason string

const (
	ReasonAllChecksPassed   DecisionReason = "all_checks_passed"
	ReasonSanctioned        DecisionReason = "sanctioned"
	ReasonInvalidCitizen    DecisionReason = "invalid_citizen"
	ReasonUnderage          DecisionReason = "underage"
	ReasonMissingCredential DecisionReason = "missing_credential"
	ReasonNotSanctioned     DecisionReason = "not_sanctioned"
)

// EvaluateRequest is the domain-level input for decision evaluation.
type EvaluateRequest struct {
	UserID     id.UserID
	Purpose    Purpose
	NationalID id.NationalID
}

// EvaluateResult is the structured outcome of a decision evaluation.
type EvaluateResult struct {
	Status      DecisionOutcome
	Reason      DecisionReason
	Conditions  []string
	Evidence    EvidenceSummary
	EvaluatedAt time.Time
}

// EvidenceSummary captures the non-PII evidence used in the decision.
type EvidenceSummary struct {
	CitizenValid    *bool
	SanctionsListed bool
	HasCredential   *bool
	IsOver18        *bool
}

// GatheredEvidence holds raw evidence before rule evaluation.
// Internal use only - not exposed in API responses.
// Uses contract types for cross-module boundary safety.
type GatheredEvidence struct {
	Citizen    *registrycontracts.CitizenRecord
	Sanctions  *registrycontracts.SanctionsRecord
	Credential *vccontracts.CredentialPresence
	FetchedAt  time.Time
	Latencies  EvidenceLatencies
}

// EvidenceLatencies tracks per-source fetch times for metrics.
type EvidenceLatencies struct {
	Citizen    time.Duration
	Sanctions  time.Duration
	Credential time.Duration
}
