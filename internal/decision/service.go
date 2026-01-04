package decision

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	registrycontracts "credo/contracts/registry"
	"credo/internal/decision/metrics"
	"credo/internal/decision/ports"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	"credo/pkg/platform/audit/publishers/compliance"
	"credo/pkg/requestcontext"
)

const (
	// evidenceTimeout is the maximum time to wait for all evidence to be gathered.
	evidenceTimeout = 5 * time.Second

	// consentPurpose is the consent purpose required for decision evaluation.
	consentPurpose id.ConsentPurpose = id.ConsentPurposeDecision
)

// Service evaluates identity, registry outputs, and VC claims to produce a
// final decision. The goal is to keep the rules centralized and testable.
type Service struct {
	registry ports.RegistryPort
	vc       ports.VCPort
	consent  ports.ConsentPort
	auditor  *compliance.Publisher
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
// Returns an error when required dependencies are nil; treat this as startup
// misconfiguration. All ports are required for compliance: consent gates data
// access and the auditor ensures regulatory audit trail.
func New(
	registry ports.RegistryPort,
	vc ports.VCPort,
	consent ports.ConsentPort,
	auditor *compliance.Publisher,
	opts ...Option,
) (*Service, error) {
	if registry == nil {
		return nil, errors.New("decision.New: registry port is required")
	}
	if vc == nil {
		return nil, errors.New("decision.New: vc port is required")
	}
	if consent == nil {
		return nil, errors.New("decision.New: consent port is required for compliance")
	}
	if auditor == nil {
		return nil, errors.New("decision.New: auditor is required for compliance audit trail")
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
	return s, nil
}

// Evaluate performs a complete decision evaluation for the given request.
// It checks consent, gathers registry/VC evidence, evaluates rules, emits an audit event,
// and records metrics using a single evaluation timestamp.
//
// Usage: callers should pass validated identifiers from a trusted boundary.
//
// Side effects: calls consent and evidence services (with timeouts and goroutines),
// emits audit events, logs audit failures, and records metrics.
//
// Errors: propagates consent/evidence errors; audit failures are fail-closed for
// all decision types (compliance requirement).
func (s *Service) Evaluate(ctx context.Context, req EvaluateRequest) (*EvaluateResult, error) {
	// Single authoritative timestamp for the entire evaluation.
	// Extracted from context (set by middleware) for deterministic testing and consistent audit trails.
	evalTime := requestcontext.Now(ctx)
	defer func() {
		if s.metrics != nil {
			s.metrics.ObserveEvaluateLatency(time.Since(evalTime))
		}
	}()

	// Check consent before accessing registry data.
	//
	// TOCTOU Note: There is a small window (~5s max, bounded by evidenceTimeout) between
	// consent verification and evidence access. If consent is revoked during this window,
	// evidence may be accessed without active consent. This is an accepted tradeoff:
	// - Window is bounded and short (< 5 seconds)
	// - Alternative (consent-per-fetch) adds latency and complexity
	// - Audit trail captures consent state at evaluation time
	// - For stricter requirements, consider consent-aware adapter pattern.
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

	// Evaluate rules (pure domain logic)
	outcome := EvaluateDecision(req.Purpose, input)

	// Build result (pure domain logic)
	result := BuildResult(req.Purpose, outcome, evidence, derived, evalTime)

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

// requireConsent enforces the decision consent gate before evidence access.
// Side effects: calls the consent service and returns its error verbatim.
func (s *Service) requireConsent(ctx context.Context, userID id.UserID) error {
	return s.consent.RequireConsent(ctx, userID, consentPurpose)
}

func (s *Service) deriveIdentity(userID id.UserID, evidence *GatheredEvidence, evalTime time.Time) DerivedIdentity {
	derived := DerivedIdentity{
		PseudonymousID: userID,
	}

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

	if evidence.Credential != nil && evidence.Credential.Exists {
		input.Credential = evidence.Credential.Claims
	}

	return input
}

// emitAudit publishes a decision audit event with fail-closed semantics.
//
// Side effects: writes audit records and logs on failure.
//
// All decision events are fail-closed: audit failure blocks the response.
// Both sanctions and age verification involve consent gating and regulated
// identity verification, making guaranteed audit persistence a compliance requirement.
func (s *Service) emitAudit(ctx context.Context, req EvaluateRequest, result *EvaluateResult, evalTime time.Time) error {
	event := audit.ComplianceEvent{
		Timestamp:     evalTime,
		UserID:        req.UserID,
		Action:        string(audit.EventDecisionMade),
		Purpose:       string(req.Purpose),
		Decision:      string(result.Status),
		SubjectIDHash: hashSubjectID(req.NationalID.String()),
		RequestID:     requestcontext.RequestID(ctx),
	}

	if err := s.auditor.Emit(ctx, event); err != nil {
		if s.logger != nil {
			s.logger.ErrorContext(ctx, "CRITICAL: audit failed for decision - blocking response",
				"user_id", req.UserID,
				"purpose", req.Purpose,
				"error", err,
			)
		}
		return dErrors.New(dErrors.CodeInternal, "decision audit unavailable")
	}
	return nil
}

// hashSubjectID produces a SHA-256 hash of the subject identifier for audit traceability.
// This allows compliance teams to correlate decisions without storing raw PII in audit logs.
func hashSubjectID(subjectID string) string {
	h := sha256.Sum256([]byte(subjectID))
	return hex.EncodeToString(h[:])
}
