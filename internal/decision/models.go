package decision

import (
	"time"

	registrycontracts "credo/contracts/registry"
	authModel "credo/internal/auth/models"
	"credo/internal/evidence/vc"
	id "credo/pkg/domain"
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
	Credential vc.Claims
}

// DerivedIdentityFromCitizen strips PII while producing attributes required for
// decisions in regulated mode.
func DerivedIdentityFromCitizen(user authModel.User, citizen registrycontracts.CitizenRecord) DerivedIdentity {
	isOver18 := deriveIsOver18(citizen.DateOfBirth)
	return DerivedIdentity{
		PseudonymousID: user.ID, // treat as pseudonymous identifier; avoid emails/names.
		IsOver18:       isOver18,
		CitizenValid:   citizen.Valid,
	}
}

func deriveIsOver18(dob string) bool {
	if dob == "" {
		return false
	}
	t, err := time.Parse("2006-01-02", dob)
	if err != nil {
		return false
	}
	years := time.Since(t).Hours() / 24 / 365.25
	return years >= 18
}
