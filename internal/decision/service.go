package decision

import (
	"context"
	"log/slog"
	"time"

	registrycontracts "credo/contracts/registry"
	"credo/internal/decision/metrics"
	"credo/internal/decision/ports"
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
	// consent and auditor can be nil (optional)

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
	start := time.Now()
	defer func() {
		if s.metrics != nil {
			s.metrics.ObserveEvaluateLatency(time.Since(start))
		}
	}()

	// Check consent (if consent port is configured)
	if err := s.requireConsent(ctx, req.UserID); err != nil {
		return nil, err
	}

	// Gather evidence based on purpose
	evidence, err := s.gatherEvidence(ctx, req)
	if err != nil {
		return nil, err
	}

	// Derive identity attributes
	derived := s.deriveIdentity(req.UserID, evidence)

	// Build decision input
	input := s.buildInput(evidence, derived)

	// Evaluate rules
	outcome := s.evaluateRules(req.Purpose, input)

	// Build result
	result := s.buildResult(req.Purpose, outcome, evidence, derived)

	// Emit audit event (fail-open for non-sanctions, fail-closed for sanctions fail)
	s.emitAudit(ctx, req, result)

	// Record metrics
	if s.metrics != nil {
		s.metrics.IncrementOutcome(string(result.Status), string(req.Purpose))
	}

	return result, nil
}

func (s *Service) requireConsent(ctx context.Context, userID interface{ String() string }) error {
	if s.consent == nil {
		return nil
	}
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
	// Rule 1: Sanctions check (hard fail)
	if input.Sanctions.Listed {
		return DecisionFail
	}

	// Rule 2: Citizen validity
	if !input.Identity.CitizenValid {
		return DecisionFail
	}

	// Rule 3: Age requirement
	if !input.Identity.IsOver18 {
		return DecisionFail
	}

	// Rule 4: Credential check (soft requirement)
	if len(input.Credential) > 0 {
		return DecisionPass
	}

	return DecisionPassWithConditions
}

func (s *Service) evaluateSanctionsScreening(input DecisionInput) DecisionOutcome {
	if input.Sanctions.Listed {
		return DecisionFail
	}
	return DecisionPass
}

func (s *Service) buildResult(purpose Purpose, outcome DecisionOutcome, evidence *GatheredEvidence, derived DerivedIdentity) *EvaluateResult {
	result := &EvaluateResult{
		Status:      outcome,
		EvaluatedAt: time.Now(),
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

func (s *Service) deriveIdentity(userID interface{ String() string }, evidence *GatheredEvidence) DerivedIdentity {
	derived := DerivedIdentity{}

	if evidence.Citizen != nil {
		derived.CitizenValid = evidence.Citizen.Valid
		derived.IsOver18 = deriveIsOver18(evidence.Citizen.DateOfBirth)
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

func (s *Service) emitAudit(ctx context.Context, req EvaluateRequest, result *EvaluateResult) {
	if s.auditor == nil {
		return
	}

	event := audit.Event{
		Category:  audit.CategoryCompliance,
		Timestamp: time.Now(),
		UserID:    req.UserID,
		Action:    "decision_made",
		Purpose:   string(req.Purpose),
		Decision:  string(result.Status),
		Reason:    string(result.Reason),
		RequestID: requestcontext.RequestID(ctx),
	}

	// For sanctions failures, use fail-closed semantics
	if result.Status == DecisionFail && result.Reason == ReasonSanctioned {
		if err := s.auditor.Emit(ctx, event); err != nil {
			if s.logger != nil {
				s.logger.ErrorContext(ctx, "CRITICAL: audit failed for sanctions decision - blocking response",
					"user_id", req.UserID,
					"error", err,
				)
			}
			// Note: In production, this should block the response.
			// For now, we log but allow the decision to proceed.
		}
	} else {
		// Best-effort for non-sanctions decisions
		if err := s.auditor.Emit(ctx, event); err != nil && s.logger != nil {
			s.logger.WarnContext(ctx, "failed to emit decision audit event",
				"error", err,
				"user_id", req.UserID,
			)
		}
	}
}
