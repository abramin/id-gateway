package decision

import (
	"context"
	"errors"
	"testing"
	"time"

	registrycontracts "credo/contracts/registry"
	vccontracts "credo/contracts/vc"
	id "credo/pkg/domain"
	"credo/pkg/platform/audit"
	"credo/pkg/platform/audit/publishers/compliance"
	auditmemory "credo/pkg/platform/audit/store/memory"
	"credo/pkg/requestcontext"

	"github.com/stretchr/testify/suite"
)

// referenceTime is a fixed time used for deterministic testing.
// All age calculations are relative to this time.
var referenceTime = time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)

// RuleEvaluationSuite tests the decision rule evaluation logic.
// These are integration tests that verify the rule chain produces correct outcomes.
type RuleEvaluationSuite struct {
	suite.Suite
	service    *Service
	registry   *mockRegistryPort
	vc         *mockVCPort
	consent    *mockConsentPort
	auditStore *auditmemory.InMemoryStore
	auditor    *compliance.Publisher
	testUserID id.UserID
	testNatID  id.NationalID
}

func TestRuleEvaluationSuite(t *testing.T) {
	suite.Run(t, new(RuleEvaluationSuite))
}

func (s *RuleEvaluationSuite) SetupTest() {
	s.registry = &mockRegistryPort{}
	s.vc = &mockVCPort{}
	s.consent = &mockConsentPort{}
	s.auditStore = auditmemory.NewInMemoryStore()
	s.auditor = compliance.New(s.auditStore)

	var err error
	s.service, err = New(s.registry, s.vc, s.consent, s.auditor)
	s.Require().NoError(err)

	// Use a valid UUID format for user ID
	s.testUserID, err = id.ParseUserID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
	s.Require().NoError(err)
	s.testNatID, err = id.ParseNationalID("TEST123456")
	s.Require().NoError(err)
}

func (s *RuleEvaluationSuite) TestAgeVerificationRuleChain() {
	s.Run("sanctions failure takes priority (Rule 1)", func() {
		s.registry.citizen = &registrycontracts.CitizenRecord{
			Valid:       true,
			DateOfBirth: "1990-01-15",
		}
		s.registry.sanctions = &registrycontracts.SanctionsRecord{Listed: true}
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
		s.registry.citizen = &registrycontracts.CitizenRecord{
			Valid:       false,
			DateOfBirth: "1990-01-15",
		}
		s.registry.sanctions = &registrycontracts.SanctionsRecord{Listed: false}
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
		// Born 10 years before referenceTime = underage (deterministic)
		dob := referenceTime.AddDate(-10, 0, 0).Format("2006-01-02")
		s.registry.citizen = &registrycontracts.CitizenRecord{
			Valid:       true,
			DateOfBirth: dob,
		}
		s.registry.sanctions = &registrycontracts.SanctionsRecord{Listed: false}
		s.vc.credential = nil

		// Inject fixed time for deterministic evaluation
		ctx := requestcontext.WithTime(context.Background(), referenceTime)
		result, err := s.service.Evaluate(ctx, EvaluateRequest{
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
		s.registry.citizen = &registrycontracts.CitizenRecord{
			Valid:       true,
			DateOfBirth: "1990-01-15",
		}
		s.registry.sanctions = &registrycontracts.SanctionsRecord{Listed: false}
		s.vc.credential = &vccontracts.CredentialPresence{
			Exists: true,
			Claims: map[string]any{"is_over_18": true},
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
		s.registry.citizen = &registrycontracts.CitizenRecord{
			Valid:       true,
			DateOfBirth: "1990-01-15",
		}
		s.registry.sanctions = &registrycontracts.SanctionsRecord{Listed: false}
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
		s.registry.sanctions = &registrycontracts.SanctionsRecord{Listed: false}

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
		s.registry.sanctions = &registrycontracts.SanctionsRecord{Listed: true}

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

	s.Run("does not fetch evidence when consent check fails", func() {
		s.consent.calls = 0
		s.registry.calls = 0
		s.vc.calls = 0
		s.consent.err = errors.New("consent required but not granted")

		_, err := s.service.Evaluate(context.Background(), EvaluateRequest{
			UserID:     s.testUserID,
			Purpose:    PurposeAgeVerification,
			NationalID: s.testNatID,
		})

		s.Error(err)
		s.Equal(1, s.consent.calls, "consent should be checked once")
		s.Equal(0, s.registry.calls, "registry should not be called when consent fails")
		s.Equal(0, s.vc.calls, "vc store should not be called when consent fails")
	})
}

func (s *RuleEvaluationSuite) TestAuditEmission() {
	s.Run("emits audit event on successful evaluation", func() {
		s.registry.citizen = &registrycontracts.CitizenRecord{
			Valid:       true,
			DateOfBirth: "1990-01-15",
		}
		s.registry.sanctions = &registrycontracts.SanctionsRecord{Listed: false}
		s.auditStore.Clear() // reset

		_, err := s.service.Evaluate(context.Background(), EvaluateRequest{
			UserID:     s.testUserID,
			Purpose:    PurposeAgeVerification,
			NationalID: s.testNatID,
		})

		s.Require().NoError(err)
		events, err := s.auditStore.ListAll(context.Background())
		s.Require().NoError(err)
		s.Len(events, 1)
		s.Equal("decision_made", events[0].Action)
		s.Equal(audit.CategoryCompliance, events[0].Category)
	})

	s.Run("includes subject ID hash in audit event", func() {
		s.registry.citizen = &registrycontracts.CitizenRecord{
			Valid:       true,
			DateOfBirth: "1990-01-15",
		}
		s.registry.sanctions = &registrycontracts.SanctionsRecord{Listed: false}
		s.auditStore.Clear() // reset

		_, err := s.service.Evaluate(context.Background(), EvaluateRequest{
			UserID:     s.testUserID,
			Purpose:    PurposeAgeVerification,
			NationalID: s.testNatID,
		})

		s.Require().NoError(err)
		events, err := s.auditStore.ListAll(context.Background())
		s.Require().NoError(err)
		s.Len(events, 1)
		s.NotEmpty(events[0].SubjectIDHash, "audit event should include hashed subject ID for traceability")
	})
}

func (s *RuleEvaluationSuite) TestAuditFailureSemantics() {
	// Helper to create a service with a failing audit store
	createServiceWithFailingAudit := func() *Service {
		failingStore := &failingAuditStore{err: errors.New("audit service unavailable")}
		failingAuditor := compliance.New(failingStore)
		svc, err := New(s.registry, s.vc, s.consent, failingAuditor)
		s.Require().NoError(err)
		return svc
	}

	s.Run("audit failure blocks sanctions screening response (fail-closed)", func() {
		s.registry.sanctions = &registrycontracts.SanctionsRecord{Listed: true}
		svc := createServiceWithFailingAudit()

		_, err := svc.Evaluate(context.Background(), EvaluateRequest{
			UserID:     s.testUserID,
			Purpose:    PurposeSanctionsScreening,
			NationalID: s.testNatID,
		})

		s.Error(err)
		s.Contains(err.Error(), "audit unavailable")
	})

	s.Run("audit failure blocks sanctioned age verification response (fail-closed)", func() {
		s.registry.citizen = &registrycontracts.CitizenRecord{
			Valid:       true,
			DateOfBirth: "1990-01-15",
		}
		s.registry.sanctions = &registrycontracts.SanctionsRecord{Listed: true}
		svc := createServiceWithFailingAudit()

		_, err := svc.Evaluate(context.Background(), EvaluateRequest{
			UserID:     s.testUserID,
			Purpose:    PurposeAgeVerification,
			NationalID: s.testNatID,
		})

		s.Error(err)
		s.Contains(err.Error(), "audit unavailable")
	})

	s.Run("audit failure blocks all age verification responses (fail-closed)", func() {
		s.registry.citizen = &registrycontracts.CitizenRecord{
			Valid:       true,
			DateOfBirth: "1990-01-15",
		}
		s.registry.sanctions = &registrycontracts.SanctionsRecord{Listed: false}
		svc := createServiceWithFailingAudit()

		_, err := svc.Evaluate(context.Background(), EvaluateRequest{
			UserID:     s.testUserID,
			Purpose:    PurposeAgeVerification,
			NationalID: s.testNatID,
		})

		s.Error(err, "all decision types are fail-closed for compliance")
		s.Contains(err.Error(), "audit unavailable")
	})
}

func (s *RuleEvaluationSuite) TestEvidenceNoPII() {
	s.Run("result contains only derived flags, no raw PII", func() {
		// Contract types only contain PII-light fields (DateOfBirth, Valid)
		// ensuring no full name, national ID, or address crosses module boundaries
		s.registry.citizen = &registrycontracts.CitizenRecord{
			DateOfBirth: "1990-01-15",
			Valid:       true,
		}
		s.registry.sanctions = &registrycontracts.SanctionsRecord{Listed: false}

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

func (s *RuleEvaluationSuite) TestCredentialLookupSoftFail() {
	s.Run("credential lookup error degrades to pass_with_conditions", func() {
		s.registry.citizen = &registrycontracts.CitizenRecord{
			Valid:       true,
			DateOfBirth: "1990-01-15",
		}
		s.registry.sanctions = &registrycontracts.SanctionsRecord{Listed: false}
		s.vc.err = errors.New("vc store unavailable")

		result, err := s.service.Evaluate(context.Background(), EvaluateRequest{
			UserID:     s.testUserID,
			Purpose:    PurposeAgeVerification,
			NationalID: s.testNatID,
		})

		s.NoError(err)
		s.Equal(DecisionPassWithConditions, result.Status)
		s.Equal(ReasonMissingCredential, result.Reason)
		s.NotNil(result.Evidence.HasCredential)
		s.False(*result.Evidence.HasCredential)
	})
}

// =============================================================================
// Mock implementations
// =============================================================================

type mockRegistryPort struct {
	citizen   *registrycontracts.CitizenRecord
	sanctions *registrycontracts.SanctionsRecord
	err       error
	calls     int
}

func (m *mockRegistryPort) CheckCitizen(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*registrycontracts.CitizenRecord, error) {
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	return m.citizen, nil
}

func (m *mockRegistryPort) CheckSanctions(ctx context.Context, userID id.UserID, nationalID id.NationalID) (*registrycontracts.SanctionsRecord, error) {
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	return m.sanctions, nil
}

type mockVCPort struct {
	credential *vccontracts.CredentialPresence
	err        error
	calls      int
}

func (m *mockVCPort) FindCredentialPresence(ctx context.Context, userID id.UserID, credType vccontracts.CredentialType) (*vccontracts.CredentialPresence, error) {
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	if m.credential == nil {
		return &vccontracts.CredentialPresence{Exists: false}, nil
	}
	return m.credential, nil
}

type mockConsentPort struct {
	err   error
	calls int
}

func (m *mockConsentPort) RequireConsent(ctx context.Context, userID id.UserID, purpose id.ConsentPurpose) error {
	m.calls++
	return m.err
}

// failingAuditStore is a test double that always returns an error.
// Used to test fail-closed audit semantics.
type failingAuditStore struct {
	err error
}

func (f *failingAuditStore) Append(_ context.Context, _ audit.Event) error {
	return f.err
}

func (f *failingAuditStore) ListByUser(_ context.Context, _ id.UserID) ([]audit.Event, error) {
	return nil, f.err
}

func (f *failingAuditStore) ListAll(_ context.Context) ([]audit.Event, error) {
	return nil, f.err
}

func (f *failingAuditStore) ListRecent(_ context.Context, _ int) ([]audit.Event, error) {
	return nil, f.err
}
