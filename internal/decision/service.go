package decision

import (
	"context"
	"log/slog"
	"time"

	registrycontracts "credo/contracts/registry"
	"credo/internal/decision/metrics"
	"credo/internal/decision/ports"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	"credo/pkg/requestcontext"
)

const (
	// evidenceTimeout is the maximum time to wait for all evidence to be gathered.
	evidenceTimeout = 5 * time.Second

	// consentPurpose is the consent purpose required for decision evaluation.
	consentPurpose = "decision_evaluation"
)

type AuditPublisher interface {
	Emit(ctx context.Context, event audit.Event) error
}

// Service evaluates identity, registry outputs, and VC claims to produce a
// final decision. The goal is to keep the rules centralized and testable.
type Service struct {
	registry ports.RegistryPort
	vc       ports.VCPort
	consent  ports.ConsentPort
	auditor  AuditPublisher
	metrics  *metrics.Metrics
	logger   *slog.Logger
}

// Option configures the Service.
type Option func(*Service)

// WithMetrics sets the metrics collector for the service.
func WithMetrics(m *metrics.Metrics) Option {
	return func(s *Service) {
		s.metrics = m
	}
}

// WithLogger sets the logger for the service.
func WithLogger(l *slog.Logger) Option {
	return func(s *Service) {
		s.logger = l
	}
}

// New creates a new decision service with required dependencies.
// Panics if required dependencies are nil - fail fast at startup.
// All ports are required for compliance: consent gates data access,
// auditor ensures regulatory audit trail.
func New(
	registry ports.RegistryPort,
	vc ports.VCPort,
	consent ports.ConsentPort,
	auditor AuditPublisher,
	opts ...Option,
) *Service {
	if registry == nil {
		panic("decision.New: registry port is required")
	}
	if vc == nil {
		panic("decision.New: vc port is required")
	}
	if consent == nil {
		panic("decision.New: consent port is required for compliance")
	}
	if auditor == nil {
		panic("decision.New: auditor is required for compliance audit trail")
	}

	s := &Service{
		registry: registry,
		vc:       vc,
		consent:  consent,
		auditor:  auditor,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Evaluate performs a complete decision evaluation for the given request.
// This is the main entry point that orchestrates evidence gathering and rule evaluation.
func (s *Service) Evaluate(ctx context.Context, req EvaluateRequest) (*EvaluateResult, error) {
	// Single authoritative timestamp for the entire evaluation.
	// Injected into all functions for deterministic testing and consistent audit trails.
	evalTime := time.Now()
	defer func() {
		if s.metrics != nil {
			s.metrics.ObserveEvaluateLatency(time.Since(evalTime))
		}
	}()

	// Check consent (if consent port is configured)
	if err := s.requireConsent(ctx, req.UserID); err != nil {
		return nil, err
	}

	// Gather evidence based on purpose
	evidence, err := s.gatherEvidence(ctx, req, evalTime)
	if err != nil {
		return nil, err
	}

	// Derive identity attributes
	derived := s.deriveIdentity(req.UserID, evidence, evalTime)

	// Build decision input
	input := s.buildInput(evidence, derived)

	// Evaluate rules
	outcome := s.evaluateRules(req.Purpose, input)

	// Build result
	result := s.buildResult(req.Purpose, outcome, evidence, derived, evalTime)

	// Emit audit event (fail-open for non-sanctions, fail-closed for sanctions)
	if err := s.emitAudit(ctx, req, result, evalTime); err != nil {
		return nil, err
	}

	// Record metrics
	if s.metrics != nil {
		s.metrics.IncrementOutcome(string(result.Status), string(req.Purpose))
	}

	return result, nil
}

func (s *Service) requireConsent(ctx context.Context, userID interface{ String() string }) error {
	return s.consent.RequireConsent(ctx, userID.String(), consentPurpose)
}

// evaluateRules applies purpose-specific rules to produce an outcome.
// This is the pure rule evaluation logic - no I/O, no side effects.
func (s *Service) evaluateRules(purpose Purpose, input DecisionInput) DecisionOutcome {
	switch purpose {
	case PurposeAgeVerification:
		return s.evaluateAgeVerification(input)
	case PurposeSanctionsScreening:
		return s.evaluateSanctionsScreening(input)
	default:
		return DecisionFail
	}
}

func (s *Service) evaluateAgeVerification(input DecisionInput) DecisionOutcome {
	// Rule 1: Sanctions check (hard fail) - compliance-critical
	if input.IsSanctioned() {
		return DecisionFail
	}

	// Rule 2: Citizen validity - identity baseline
	if !input.IsCitizenValid() {
		return DecisionFail
	}

	// Rule 3: Age requirement - purpose-specific
	if !input.IsOfLegalAge() {
		return DecisionFail
	}

	// Rule 4: Credential check (soft requirement for full pass)
	if len(input.Credential) > 0 {
		return DecisionPass
	}

	return DecisionPassWithConditions
}

func (s *Service) evaluateSanctionsScreening(input DecisionInput) DecisionOutcome {
	if input.IsSanctioned() {
		return DecisionFail
	}
	return DecisionPass
}

func (s *Service) buildResult(purpose Purpose, outcome DecisionOutcome, evidence *GatheredEvidence, derived DerivedIdentity, evalTime time.Time) *EvaluateResult {
	result := &EvaluateResult{
		Status:      outcome,
		EvaluatedAt: evalTime,
		Conditions:  []string{},
		Evidence: EvidenceSummary{
			SanctionsListed: evidence.Sanctions != nil && evidence.Sanctions.Listed,
		},
	}

	// Set reason and conditions based on outcome and purpose
	switch purpose {
	case PurposeAgeVerification:
		result = s.buildAgeVerificationResult(result, outcome, evidence, derived)
	case PurposeSanctionsScreening:
		result = s.buildSanctionsResult(result, outcome, evidence)
	}

	return result
}

func (s *Service) buildAgeVerificationResult(result *EvaluateResult, outcome DecisionOutcome, evidence *GatheredEvidence, derived DerivedIdentity) *EvaluateResult {
	// Set evidence fields
	if evidence.Citizen != nil {
		valid := evidence.Citizen.Valid
		result.Evidence.CitizenValid = &valid
	}
	over18 := derived.IsOver18
	result.Evidence.IsOver18 = &over18
	hasCred := evidence.Credential != nil
	result.Evidence.HasCredential = &hasCred

	// Set reason based on failure point
	switch outcome {
	case DecisionFail:
		if evidence.Sanctions != nil && evidence.Sanctions.Listed {
			result.Reason = ReasonSanctioned
		} else if evidence.Citizen == nil || !evidence.Citizen.Valid {
			result.Reason = ReasonInvalidCitizen
		} else if !derived.IsOver18 {
			result.Reason = ReasonUnderage
		}
	case DecisionPass:
		result.Reason = ReasonAllChecksPassed
	case DecisionPassWithConditions:
		result.Reason = ReasonMissingCredential
		result.Conditions = []string{"obtain_age_credential"}
	}

	return result
}

func (s *Service) buildSanctionsResult(result *EvaluateResult, outcome DecisionOutcome, evidence *GatheredEvidence) *EvaluateResult {
	switch outcome {
	case DecisionFail:
		result.Reason = ReasonSanctioned
	case DecisionPass:
		result.Reason = ReasonNotSanctioned
	}
	return result
}

func (s *Service) deriveIdentity(userID interface{ String() string }, evidence *GatheredEvidence, evalTime time.Time) DerivedIdentity {
	derived := DerivedIdentity{}

	if evidence.Citizen != nil {
		derived.CitizenValid = evidence.Citizen.Valid
		derived.IsOver18 = deriveIsOver18(evidence.Citizen.DateOfBirth, evalTime)
	}

	return derived
}

func (s *Service) buildInput(evidence *GatheredEvidence, derived DerivedIdentity) DecisionInput {
	input := DecisionInput{
		Identity: derived,
	}

	if evidence.Sanctions != nil {
		input.Sanctions = registrycontracts.SanctionsRecord{
			Listed: evidence.Sanctions.Listed,
		}
	}

	if evidence.Credential != nil {
		input.Credential = evidence.Credential.Claims
	}

	return input
}

// emitAudit publishes a decision audit event.
//
// Audit semantics vary by decision type:
//   - Sanctions decisions: fail-closed (audit failure blocks response).
//     Regulatory compliance requires audit trail guarantees for high-consequence decisions.
//   - Age verification decisions: fail-open (audit failure is best-effort).
//     Advisory decisions can proceed without guaranteed audit persistence.
func (s *Service) emitAudit(ctx context.Context, req EvaluateRequest, result *EvaluateResult, evalTime time.Time) error {
	event := audit.Event{
		Category:  audit.EventDecisionMade.Category(),
		Timestamp: evalTime,
		UserID:    req.UserID,
		Action:    string(audit.EventDecisionMade),
		Purpose:   string(req.Purpose),
		Decision:  string(result.Status),
		Reason:    string(result.Reason),
		RequestID: requestcontext.RequestID(ctx),
	}

	// For sanctions-related decisions, use fail-closed semantics.
	// The audit trail MUST be recorded before returning the decision.
	isSanctionsRelated := result.Reason == ReasonSanctioned || req.Purpose == PurposeSanctionsScreening
	if isSanctionsRelated {
		if err := s.auditor.Emit(ctx, event); err != nil {
			if s.logger != nil {
				s.logger.ErrorContext(ctx, "CRITICAL: audit failed for sanctions decision - blocking response",
					"user_id", req.UserID,
					"purpose", req.Purpose,
					"error", err,
				)
			}
			return dErrors.New(dErrors.CodeInternal, "decision audit unavailable")
		}
		return nil
	}

	// Best-effort for non-sanctions decisions
	if err := s.auditor.Emit(ctx, event); err != nil && s.logger != nil {
		s.logger.WarnContext(ctx, "failed to emit decision audit event",
			"error", err,
			"user_id", req.UserID,
		)
	}
	return nil
}
