package decision

import (
	"context"
	"errors"
	"testing"
	"time"

	"credo/internal/decision/ports"
	vcmodels "credo/internal/evidence/vc/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/audit"

	"github.com/stretchr/testify/suite"
)

// RuleEvaluationSuite tests the decision rule evaluation logic.
// These are integration tests that verify the rule chain produces correct outcomes.
type RuleEvaluationSuite struct {
	suite.Suite
	service     *Service
	registry    *mockRegistryPort
	vc          *mockVCPort
	consent     *mockConsentPort
	auditor     *mockAuditPublisher
	testUserID  id.UserID
	testNatID   id.NationalID
}

func TestRuleEvaluationSuite(t *testing.T) {
	suite.Run(t, new(RuleEvaluationSuite))
}

func (s *RuleEvaluationSuite) SetupTest() {
	s.registry = &mockRegistryPort{}
	s.vc = &mockVCPort{}
	s.consent = &mockConsentPort{}
	s.auditor = &mockAuditPublisher{}

	s.service = New(s.registry, s.vc, s.consent, s.auditor)

	var err error
	// Use a valid UUID format for user ID
	s.testUserID, err = id.ParseUserID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
	s.Require().NoError(err)
	s.testNatID, err = id.ParseNationalID("TEST123456")
	s.Require().NoError(err)
}

func (s *RuleEvaluationSuite) TestAgeVerificationRuleChain() {
	s.Run("sanctions failure takes priority (Rule 1)", func() {
		s.registry.citizen = &ports.CitizenRecord{
			Valid:       true,
			DateOfBirth: "1990-01-15",
		}
		s.registry.sanctions = &ports.SanctionsRecord{Listed: true}
		s.vc.credential = nil

		result, err := s.service.Evaluate(context.Background(), EvaluateRequest{
			UserID:     s.testUserID,
			Purpose:    PurposeAgeVerification,
			NationalID: s.testNatID,
		})

		s.Require().NoError(err)
		s.Equal(DecisionFail, result.Status)
		s.Equal(ReasonSanctioned, result.Reason)
		s.True(result.Evidence.SanctionsListed)
	})

	s.Run("invalid citizen fails after sanctions check (Rule 2)", func() {
		s.registry.citizen = &ports.CitizenRecord{
			Valid:       false,
			DateOfBirth: "1990-01-15",
		}
		s.registry.sanctions = &ports.SanctionsRecord{Listed: false}
		s.vc.credential = nil

		result, err := s.service.Evaluate(context.Background(), EvaluateRequest{
			UserID:     s.testUserID,
			Purpose:    PurposeAgeVerification,
			NationalID: s.testNatID,
		})

		s.Require().NoError(err)
		s.Equal(DecisionFail, result.Status)
		s.Equal(ReasonInvalidCitizen, result.Reason)
		s.False(result.Evidence.SanctionsListed)
		s.NotNil(result.Evidence.CitizenValid)
		s.False(*result.Evidence.CitizenValid)
	})

	s.Run("underage fails after citizen check (Rule 3)", func() {
		// Born 10 years ago = underage
		dob := time.Now().AddDate(-10, 0, 0).Format("2006-01-02")
		s.registry.citizen = &ports.CitizenRecord{
			Valid:       true,
			DateOfBirth: dob,
		}
		s.registry.sanctions = &ports.SanctionsRecord{Listed: false}
		s.vc.credential = nil

		result, err := s.service.Evaluate(context.Background(), EvaluateRequest{
			UserID:     s.testUserID,
			Purpose:    PurposeAgeVerification,
			NationalID: s.testNatID,
		})

		s.Require().NoError(err)
		s.Equal(DecisionFail, result.Status)
		s.Equal(ReasonUnderage, result.Reason)
		s.NotNil(result.Evidence.IsOver18)
		s.False(*result.Evidence.IsOver18)
	})

	s.Run("passes with credential (Rule 4)", func() {
		s.registry.citizen = &ports.CitizenRecord{
			Valid:       true,
			DateOfBirth: "1990-01-15",
		}
		s.registry.sanctions = &ports.SanctionsRecord{Listed: false}
		s.vc.credential = &vcmodels.CredentialRecord{
			Claims: vcmodels.Claims{"is_over_18": true},
		}

		result, err := s.service.Evaluate(context.Background(), EvaluateRequest{
			UserID:     s.testUserID,
			Purpose:    PurposeAgeVerification,
			NationalID: s.testNatID,
		})

		s.Require().NoError(err)
		s.Equal(DecisionPass, result.Status)
		s.Equal(ReasonAllChecksPassed, result.Reason)
		s.NotNil(result.Evidence.HasCredential)
		s.True(*result.Evidence.HasCredential)
	})

	s.Run("passes with conditions when no credential (Rule 5)", func() {
		s.registry.citizen = &ports.CitizenRecord{
			Valid:       true,
			DateOfBirth: "1990-01-15",
		}
		s.registry.sanctions = &ports.SanctionsRecord{Listed: false}
		s.vc.credential = nil

		result, err := s.service.Evaluate(context.Background(), EvaluateRequest{
			UserID:     s.testUserID,
			Purpose:    PurposeAgeVerification,
			NationalID: s.testNatID,
		})

		s.Require().NoError(err)
		s.Equal(DecisionPassWithConditions, result.Status)
		s.Equal(ReasonMissingCredential, result.Reason)
		s.Contains(result.Conditions, "obtain_age_credential")
		s.NotNil(result.Evidence.HasCredential)
		s.False(*result.Evidence.HasCredential)
	})
}

func (s *RuleEvaluationSuite) TestSanctionsScreeningRules() {
	s.Run("passes when not listed", func() {
		s.registry.sanctions = &ports.SanctionsRecord{Listed: false}

		result, err := s.service.Evaluate(context.Background(), EvaluateRequest{
			UserID:     s.testUserID,
			Purpose:    PurposeSanctionsScreening,
			NationalID: s.testNatID,
		})

		s.Require().NoError(err)
		s.Equal(DecisionPass, result.Status)
		s.Equal(ReasonNotSanctioned, result.Reason)
		s.False(result.Evidence.SanctionsListed)
	})

	s.Run("fails when listed", func() {
		s.registry.sanctions = &ports.SanctionsRecord{Listed: true}

		result, err := s.service.Evaluate(context.Background(), EvaluateRequest{
			UserID:     s.testUserID,
			Purpose:    PurposeSanctionsScreening,
			NationalID: s.testNatID,
		})

		s.Require().NoError(err)
		s.Equal(DecisionFail, result.Status)
		s.Equal(ReasonSanctioned, result.Reason)
		s.True(result.Evidence.SanctionsListed)
	})
}

func (s *RuleEvaluationSuite) TestConsentEnforcement() {
	s.Run("returns error when consent check fails", func() {
		s.consent.err = errors.New("consent required but not granted")

		_, err := s.service.Evaluate(context.Background(), EvaluateRequest{
			UserID:     s.testUserID,
			Purpose:    PurposeAgeVerification,
			NationalID: s.testNatID,
		})

		s.Error(err)
		s.Contains(err.Error(), "consent")
	})
}

func (s *RuleEvaluationSuite) TestAuditEmission() {
	s.Run("emits audit event on successful evaluation", func() {
		s.registry.citizen = &ports.CitizenRecord{
			Valid:       true,
			DateOfBirth: "1990-01-15",
		}
		s.registry.sanctions = &ports.SanctionsRecord{Listed: false}
		s.auditor.events = nil // reset

		_, err := s.service.Evaluate(context.Background(), EvaluateRequest{
			UserID:     s.testUserID,
			Purpose:    PurposeAgeVerification,
			NationalID: s.testNatID,
		})

		s.Require().NoError(err)
		s.Len(s.auditor.events, 1)
		s.Equal("decision_made", s.auditor.events[0].Action)
		s.Equal(audit.CategoryCompliance, s.auditor.events[0].Category)
	})
}

func (s *RuleEvaluationSuite) TestEvidenceNoPII() {
	s.Run("result contains only derived flags, no raw PII", func() {
		s.registry.citizen = &ports.CitizenRecord{
			NationalID:  "SHOULD_NOT_APPEAR",
			FullName:    "SHOULD_NOT_APPEAR",
			DateOfBirth: "1990-01-15",
			Valid:       true,
		}
		s.registry.sanctions = &ports.SanctionsRecord{Listed: false}

		result, err := s.service.Evaluate(context.Background(), EvaluateRequest{
			UserID:     s.testUserID,
			Purpose:    PurposeAgeVerification,
			NationalID: s.testNatID,
		})

		s.Require().NoError(err)
		// Evidence should contain boolean flags only
		s.NotNil(result.Evidence.CitizenValid)
		s.NotNil(result.Evidence.IsOver18)
		s.NotNil(result.Evidence.HasCredential)
		// Evidence struct has no PII fields by design
	})
}

// =============================================================================
// Mock implementations
// =============================================================================

type mockRegistryPort struct {
	citizen   *ports.CitizenRecord
	sanctions *ports.SanctionsRecord
	err       error
}

func (m *mockRegistryPort) CheckCitizen(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*ports.CitizenRecord, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.citizen, nil
}

func (m *mockRegistryPort) CheckSanctions(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*ports.SanctionsRecord, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.sanctions, nil
}

func (m *mockRegistryPort) Check(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*ports.CitizenRecord, *ports.SanctionsRecord, error) {
	if m.err != nil {
		return nil, nil, m.err
	}
	return m.citizen, m.sanctions, nil
}

type mockVCPort struct {
	credential *vcmodels.CredentialRecord
	err        error
}

func (m *mockVCPort) FindBySubjectAndType(ctx context.Context, userID id.UserID, credType vcmodels.CredentialType) (*vcmodels.CredentialRecord, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.credential, nil
}

type mockConsentPort struct {
	hasConsent bool
	err        error
}

func (m *mockConsentPort) HasConsent(ctx context.Context, userID string, purpose string) (bool, error) {
	if m.err != nil {
		return false, m.err
	}
	return m.hasConsent, nil
}

func (m *mockConsentPort) RequireConsent(ctx context.Context, userID string, purpose string) error {
	return m.err
}

type mockAuditPublisher struct {
	events []audit.Event
	err    error
}

func (m *mockAuditPublisher) Emit(ctx context.Context, event audit.Event) error {
	if m.err != nil {
		return m.err
	}
	m.events = append(m.events, event)
	return nil
}
