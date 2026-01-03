package service

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"

	consentmetrics "credo/internal/consent/metrics"
	"credo/internal/consent/models"
	id "credo/pkg/domain"
	pkgerrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	"credo/pkg/platform/audit/publishers/compliance"
	"credo/pkg/platform/middleware/admin"
	"credo/pkg/platform/sentinel"
	"credo/pkg/requestcontext"
)

// Store defines the persistence interface for consent records.
// Error Contract:
// - FindByScope returns store.ErrNotFound when no record exists
// - Save returns store.ErrConflict when a record already exists
// - Execute returns store.ErrNotFound when no record exists
// - Other methods return nil on success or wrapped errors on failure
type Store interface {
	Save(ctx context.Context, consent *models.Record) error
	FindByScope(ctx context.Context, scope models.ConsentScope) (*models.Record, error)
	ListByUser(ctx context.Context, userID id.UserID, filter *models.RecordFilter) ([]*models.Record, error)
	Update(ctx context.Context, consent *models.Record) error
	RevokeAllByUser(ctx context.Context, userID id.UserID, now time.Time) (int, error)
	DeleteByUser(ctx context.Context, userID id.UserID) error
	Execute(ctx context.Context, scope models.ConsentScope, validate func(*models.Record) error, mutate func(*models.Record) bool) (*models.Record, error)
}

// Option configures Service during initialization.
type Option func(*Service)

const (
	defaultConsentTTL             = 365 * 24 * time.Hour // 1 year
	defaultGrantIdempotencyWindow = 5 * time.Minute
	defaultReGrantCooldown        = models.DefaultReGrantCooldown
)

// Service persists consent decisions and enforces lifecycle rules per PRD-002.
// It coordinates store writes, audit events, and metrics for consent operations.
type Service struct {
	store                  Store
	tx                     ConsentStoreTx
	auditor                *compliance.Publisher
	metrics                *consentmetrics.Metrics
	logger                 *slog.Logger
	consentTTL             time.Duration
	grantIdempotencyWindow time.Duration
	reGrantCooldown        time.Duration
}

// New constructs a consent service with defaults applied.
func New(store Store, auditor *compliance.Publisher, logger *slog.Logger, opts ...Option) *Service {
	svc := &Service{
		store:                  store,
		tx:                     newInMemoryConsentTx(store),
		auditor:                auditor,
		logger:                 logger,
		consentTTL:             defaultConsentTTL,
		grantIdempotencyWindow: defaultGrantIdempotencyWindow,
		reGrantCooldown:        defaultReGrantCooldown,
	}
	for _, opt := range opts {
		opt(svc)
	}
	// Validate and apply defaults if needed
	if svc.consentTTL <= 0 {
		svc.consentTTL = defaultConsentTTL
	}
	if svc.grantIdempotencyWindow <= 0 {
		svc.grantIdempotencyWindow = defaultGrantIdempotencyWindow
	}
	if svc.reGrantCooldown <= 0 {
		svc.reGrantCooldown = defaultReGrantCooldown
	}
	return svc
}

// WithTx sets a custom transaction provider for the service.
func WithTx(tx ConsentStoreTx) Option {
	return func(s *Service) {
		s.tx = tx
	}
}

// WithMetrics sets the metrics instance for the service.
func WithMetrics(m *consentmetrics.Metrics) Option {
	return func(s *Service) {
		s.metrics = m
	}
}

// WithLogger sets the logger instance for the service.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Service) {
		s.logger = logger
	}
}

// WithConsentTTL configures the time-to-live duration for granted consents.
// If not set or set to zero/negative, defaults to 1 year.
func WithConsentTTL(ttl time.Duration) Option {
	return func(s *Service) {
		if ttl > 0 {
			s.consentTTL = ttl
		}
	}
}

// WithGrantWindow configures the idempotency window for repeated grants.
// If not set or set to zero/negative, defaults to 5 minutes.
func WithGrantWindow(window time.Duration) Option {
	return func(s *Service) {
		if window > 0 {
			s.grantIdempotencyWindow = window
		}
	}
}

// WithReGrantCooldown configures the minimum time after revocation before re-grant is allowed.
// This prevents rapid revoke→grant cycles that could be abused.
// If not set or set to zero/negative, defaults to 5 minutes.
func WithReGrantCooldown(cooldown time.Duration) Option {
	return func(s *Service) {
		if cooldown > 0 {
			s.reGrantCooldown = cooldown
		}
	}
}

// validatePurposes enforces that each purpose is a known enum value.
// It maps invalid inputs to a domain bad-request error for handlers.
func validatePurposes(purposes []models.Purpose) error {
	for _, purpose := range purposes {
		if !purpose.IsValid() {
			return pkgerrors.New(pkgerrors.CodeBadRequest, "invalid purpose")
		}
	}
	return nil
}

// scopeForPurpose constructs a validated ConsentScope and maps invariant failures
// to a domain bad-request error.
func scopeForPurpose(userID id.UserID, purpose models.Purpose) (models.ConsentScope, error) {
	scope, err := models.NewConsentScope(userID, purpose)
	if err != nil {
		return models.ConsentScope{}, pkgerrors.New(pkgerrors.CodeBadRequest, "invalid consent scope")
	}
	return scope, nil
}

// withUserTx runs fn inside a consent transaction and tags the context with the
// user ID for shard locking.
// Side effects: acquires a lock or DB transaction and may apply a timeout.
func (s *Service) withUserTx(ctx context.Context, userID id.UserID, fn func(ctx context.Context, store Store) error) error {
	txCtx := context.WithValue(ctx, txUserKeyCtx, userID.String())
	return s.tx.RunInTx(txCtx, fn)
}

// forEachScope applies fn to each purpose within a single transaction.
// It stops on the first error to preserve atomicity.
func (s *Service) forEachScope(
	ctx context.Context,
	userID id.UserID,
	purposes []models.Purpose,
	fn func(ctx context.Context, store Store, scope models.ConsentScope) error,
) error {
	return s.withUserTx(ctx, userID, func(txCtx context.Context, txStore Store) error {
		for _, purpose := range purposes {
			scope, err := scopeForPurpose(userID, purpose)
			if err != nil {
				return err
			}
			if err := fn(txCtx, txStore, scope); err != nil {
				return err
			}
		}
		return nil
	})
}

// Grant grants consent for the specified purposes.
// It performs transactional upserts, applies idempotency rules,
// and emits audit/metrics for any changes.
// Returns the granted records (domain objects), not HTTP response DTOs.
func (s *Service) Grant(ctx context.Context, userID id.UserID, purposes []models.Purpose) ([]*models.Record, error) {
	if userID.IsNil() {
		return nil, pkgerrors.New(pkgerrors.CodeUnauthorized, "user ID required")
	}
	if len(purposes) == 0 {
		return nil, pkgerrors.New(pkgerrors.CodeBadRequest, "purposes array must not be empty")
	}
	if err := validatePurposes(purposes); err != nil {
		return nil, err
	}

	var (
		granted []*models.Record
		effects []*grantEffect
	)
	// Wrap multi-purpose grant in transaction to ensure atomicity per AGENTS.md
	txErr := s.forEachScope(ctx, userID, purposes, func(txCtx context.Context, txStore Store, scope models.ConsentScope) error {
		record, effect, err := s.upsertGrantTx(txCtx, txStore, scope)
		if err != nil {
			return err
		}
		granted = append(granted, record)
		if effect != nil {
			effects = append(effects, effect)
		}
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}

	for _, effect := range effects {
		s.emitGrantAudit(ctx, effect.record.UserID, effect.record.Purpose, effect.timestamp)
		s.metrics.IncrementConsentsGranted(string(effect.record.Purpose))
		if !effect.wasActive {
			s.metrics.IncrementActiveConsents(1)
		}
	}

	return granted, nil
}

type grantEffect struct {
	record    *models.Record
	wasActive bool
	timestamp time.Time
}

// tryRevokeScopeTx revokes consent for a single scope inside the store Execute lock.
// It returns (nil, false, nil) when the record is missing or not revocable.
func (s *Service) tryRevokeScopeTx(ctx context.Context, txStore Store, scope models.ConsentScope, now time.Time) (*models.Record, bool, error) {
	var (
		changed bool
		updated models.Record
	)
	record, err := txStore.Execute(ctx, scope,
		func(existing *models.Record) error {
			if !existing.CanRevoke(now) {
				changed = false
				return nil
			}

			var err error
			updated, err = existing.RevokeAt(now)
			if err != nil {
				return err
			}
			changed = true
			return nil
		},
		func(existing *models.Record) bool {
			if !changed {
				return false
			}
			*existing = updated
			return true
		},
	)
	if errors.Is(err, sentinel.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		var domainErr *pkgerrors.Error
		if errors.As(err, &domainErr) {
			return nil, false, err
		}
		return nil, false, pkgerrors.Wrap(err, pkgerrors.CodeInternal, "failed to revoke consent")
	}
	return record, changed, nil
}

// upsertGrantTx applies grant rules to a single scope and persists changes atomically.
// It retries on conflict to handle concurrent grant/create races.
func (s *Service) upsertGrantTx(ctx context.Context, txStore Store, scope models.ConsentScope) (*models.Record, *grantEffect, error) {
	now := requestcontext.Now(ctx)
	for attempt := 0; attempt < 2; attempt++ {
		var eval models.GrantEvaluation

		record, err := txStore.Execute(ctx, scope,
			func(existing *models.Record) error {
				var err error
				eval, err = existing.EvaluateGrant(now, s.grantIdempotencyWindow, s.reGrantCooldown, s.consentTTL)
				return err
			},
			func(existing *models.Record) bool {
				if !eval.Changed {
					return false
				}
				*existing = eval.Updated
				return true
			},
		)
		if err == nil {
			if !eval.Changed {
				return record, nil, nil
			}
			return record, &grantEffect{record: record, wasActive: eval.WasActive, timestamp: now}, nil
		}

		if errors.Is(err, sentinel.ErrNotFound) {
			record, err = s.createGrantTx(ctx, txStore, scope, now)
			if err == nil {
				return record, &grantEffect{record: record, wasActive: false, timestamp: now}, nil
			}
			if errors.Is(err, sentinel.ErrConflict) {
				continue
			}
			return nil, nil, err
		}

		var domainErr *pkgerrors.Error
		if errors.As(err, &domainErr) {
			return nil, nil, err
		}
		return nil, nil, pkgerrors.Wrap(err, pkgerrors.CodeInternal, "failed to update consent")
	}

	return nil, nil, pkgerrors.New(pkgerrors.CodeConflict, "consent grant conflict")
}

// createGrantTx creates and persists a new consent record for the scope.
// Side effects: writes to the consent store and may return a conflict on races.
func (s *Service) createGrantTx(ctx context.Context, txStore Store, scope models.ConsentScope, now time.Time) (*models.Record, error) {
	expiry := now.Add(s.consentTTL)
	record, err := models.NewRecord(
		id.ConsentID(uuid.New()),
		scope.UserID,
		scope.Purpose,
		now,
		&expiry,
	)
	if err != nil {
		return nil, pkgerrors.Wrap(err, pkgerrors.CodeInternal, "failed to create consent record")
	}

	if err := txStore.Save(ctx, record); err != nil {
		if errors.Is(err, sentinel.ErrConflict) {
			return nil, err
		}
		return nil, pkgerrors.Wrap(err, pkgerrors.CodeInternal, "failed to save consent")
	}

	return record, nil
}

// emitGrantAudit emits the audit event for a consent grant.
func (s *Service) emitGrantAudit(ctx context.Context, userID id.UserID, purpose models.Purpose, now time.Time) {
	s.emitAudit(ctx, audit.ComplianceEvent{
		UserID:    userID,
		Purpose:   string(purpose),
		Action:    models.AuditActionConsentGranted,
		Decision:  models.AuditDecisionGranted,
		Timestamp: now,
	})
}

// Revoke revokes consent for the specified purposes.
// It skips missing, expired, or already revoked records while emitting audit/metrics
// for successful revocations. Returns domain objects, not HTTP response DTOs.
func (s *Service) Revoke(ctx context.Context, userID id.UserID, purposes []models.Purpose) ([]*models.Record, error) {
	if userID.IsNil() {
		return nil, pkgerrors.New(pkgerrors.CodeUnauthorized, "user ID required")
	}
	if err := validatePurposes(purposes); err != nil {
		return nil, err
	}

	var revoked []*models.Record
	now := requestcontext.Now(ctx)

	// Wrap multi-purpose revoke in transaction to ensure atomicity
	txErr := s.forEachScope(ctx, userID, purposes, func(txCtx context.Context, txStore Store, scope models.ConsentScope) error {
		record, changed, err := s.tryRevokeScopeTx(txCtx, txStore, scope, now)
		if err != nil {
			return err
		}
		if !changed {
			return nil
		}
		revoked = append(revoked, record)
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}

	for _, record := range revoked {
		s.emitAudit(ctx, audit.ComplianceEvent{
			UserID:    userID,
			Purpose:   string(record.Purpose),
			Action:    models.AuditActionConsentRevoked,
			Decision:  models.AuditDecisionRevoked,
			Timestamp: now,
		})
		s.metrics.IncrementConsentsRevoked(string(record.Purpose))
		s.metrics.DecrementActiveConsents(1)
	}

	return revoked, nil
}

// RevokeAll revokes all active consents for a user.
// Intended for administrative purposes. Returns the count of revoked consents.
// If an admin actor ID is present in context (via X-Admin-Actor-ID header),
// it is included in the audit event for attribution.
func (s *Service) RevokeAll(ctx context.Context, userID id.UserID) (int, error) {
	if userID.IsNil() {
		return 0, pkgerrors.New(pkgerrors.CodeBadRequest, "user ID required")
	}
	now := requestcontext.Now(ctx)
	revokedCount := 0

	// Wrap bulk revoke in transaction to ensure atomicity
	txErr := s.withUserTx(ctx, userID, func(txCtx context.Context, txStore Store) error {
		count, err := txStore.RevokeAllByUser(txCtx, userID, now)
		if err != nil {
			return pkgerrors.Wrap(err, pkgerrors.CodeInternal, "failed to revoke consents")
		}
		revokedCount = count
		return nil
	})
	if txErr != nil {
		return 0, txErr
	}

	if revokedCount > 0 {
		// Include admin actor ID for audit attribution if present
		actorID := admin.GetAdminActorID(ctx)
		s.emitAudit(ctx, audit.ComplianceEvent{
			UserID:    userID,
			Action:    models.AuditActionConsentRevoked,
			Decision:  models.AuditDecisionRevoked,
			Timestamp: now,
			ActorID:   actorID,
		})
		s.metrics.DecrementActiveConsents(float64(revokedCount))
	}

	return revokedCount, nil
}

// DeleteAll removes all consent records for a user.
// Intended for GDPR right to erasure and test cleanup.
// If an admin actor ID is present in context, it is included in the audit event.
func (s *Service) DeleteAll(ctx context.Context, userID id.UserID) error {
	if userID.IsNil() {
		return pkgerrors.New(pkgerrors.CodeBadRequest, "user ID required")
	}
	now := requestcontext.Now(ctx)

	txErr := s.withUserTx(ctx, userID, func(txCtx context.Context, txStore Store) error {
		if err := txStore.DeleteByUser(txCtx, userID); err != nil {
			return pkgerrors.Wrap(err, pkgerrors.CodeInternal, "failed to delete all consents")
		}
		return nil
	})
	if txErr != nil {
		return txErr
	}

	// Include admin actor ID for audit attribution if present
	actorID := admin.GetAdminActorID(ctx)
	s.emitAudit(ctx, audit.ComplianceEvent{
		UserID:    userID,
		Action:    models.AuditActionConsentDeleted,
		Decision:  models.AuditDecisionDeleted,
		Timestamp: now,
		ActorID:   actorID,
	})

	return nil
}

// List returns all consent records for a user.
// It applies optional filters and returns domain objects, not HTTP DTOs.
func (s *Service) List(ctx context.Context, userID id.UserID, filter *models.RecordFilter) ([]*models.Record, error) {
	if userID.IsNil() {
		return nil, pkgerrors.New(pkgerrors.CodeUnauthorized, "user ID required")
	}
	storeFilter := filter
	if filter != nil && filter.Status != nil {
		storeFilter = &models.RecordFilter{Purpose: filter.Purpose}
	}
	records, err := s.store.ListByUser(ctx, userID, storeFilter)
	if err != nil {
		return nil, pkgerrors.Wrap(err, pkgerrors.CodeInternal, "failed to list consents")
	}

	if filter != nil && (filter.Purpose != nil || filter.Status != nil) {
		records = filterRecords(records, filter, requestcontext.Now(ctx))
	}

	// Record distribution of records per user for performance monitoring
	s.metrics.ObserveRecordsPerUser(float64(len(records)))

	return records, nil
}

func filterRecords(records []*models.Record, filter *models.RecordFilter, now time.Time) []*models.Record {
	if filter == nil {
		return records
	}

	filtered := make([]*models.Record, 0, len(records))
	for _, record := range records {
		if filter.Purpose != nil && record.Purpose != *filter.Purpose {
			continue
		}
		if filter.Status != nil && record.ComputeStatus(now) != *filter.Status {
			continue
		}
		filtered = append(filtered, record)
	}
	return filtered
}

func auditReasonForRevokeAll(ctx context.Context) string {
	if admin.IsAdminRequest(ctx) {
		return models.AuditReasonSecurityConcern
	}
	return models.AuditReasonUserBulkRevocation
}

func auditReasonForDeleteAll(ctx context.Context) string {
	if admin.IsAdminRequest(ctx) {
		return models.AuditReasonGdprErasureRequest
	}
	return models.AuditReasonGdprSelfService
}

// Require enforces that a user has active consent for the given purpose.
// It records audit/metrics outcomes for missing, revoked, expired, or active states.
func (s *Service) Require(ctx context.Context, userID id.UserID, purpose models.Purpose) error {
	if userID.IsNil() {
		return pkgerrors.New(pkgerrors.CodeUnauthorized, "user ID required")
	}
	if !purpose.IsValid() {
		return pkgerrors.New(pkgerrors.CodeBadRequest, "invalid purpose")
	}

	scope, err := models.NewConsentScope(userID, purpose)
	if err != nil {
		return pkgerrors.New(pkgerrors.CodeBadRequest, "invalid consent scope")
	}

	record, err := s.store.FindByScope(ctx, scope)
	if err != nil {
		if errors.Is(err, sentinel.ErrNotFound) {
			s.recordConsentCheckOutcome(ctx, userID, purpose, outcomeMissing)
			return pkgerrors.New(pkgerrors.CodeMissingConsent, "consent not granted for required purpose")
		}
		return pkgerrors.Wrap(err, pkgerrors.CodeInternal, "failed to read consent")
	}

	now := requestcontext.Now(ctx)
	switch record.ComputeStatus(now) {
	case models.StatusRevoked:
		s.recordConsentCheckOutcome(ctx, userID, purpose, outcomeRevoked)
		return pkgerrors.New(pkgerrors.CodeInvalidConsent, "consent revoked")
	case models.StatusExpired:
		s.recordConsentCheckOutcome(ctx, userID, purpose, outcomeExpired)
		return pkgerrors.New(pkgerrors.CodeInvalidConsent, "consent expired")
	}

	s.recordConsentCheckOutcome(ctx, userID, purpose, outcomePassed)
	return nil
}

// emitAudit publishes an audit event and logs any persistence failures.
// Side effects: write to audit store, logging on failure, and request ID enrichment.
func (s *Service) emitAudit(ctx context.Context, event audit.ComplianceEvent) {
	if s.auditor == nil {
		return
	}
	// Enrich with RequestID for correlation
	if event.RequestID == "" {
		event.RequestID = requestcontext.RequestID(ctx)
	}
	if err := s.auditor.Emit(ctx, event); err != nil {
		// Log audit failures but don't fail the operation - audit is best-effort
		// for consent operations. The primary operation should still succeed.
		s.logger.ErrorContext(ctx, "failed to emit audit event",
			"error", err,
			"action", event.Action,
			"user_id", event.UserID,
			"purpose", event.Purpose,
		)
	}
}

// incrementConsentsGranted increments the consents granted metric if metrics are enabled
func (s *Service) incrementConsentsGranted(purpose models.Purpose) {
	if s.metrics != nil {
		s.metrics.IncrementConsentsGranted(string(purpose))
	}
}

// incrementConsentsRevoked increments the consents revoked metric if metrics are enabled
func (s *Service) incrementConsentsRevoked(purpose models.Purpose) {
	if s.metrics != nil {
		s.metrics.IncrementConsentsRevoked(string(purpose))
	}
}

// incrementConsentCheckPassed increments the consent check passed metric if metrics are enabled
func (s *Service) incrementConsentCheckPassed(purpose models.Purpose) {
	if s.metrics != nil {
		s.metrics.IncrementConsentCheckPassed(string(purpose))
	}
}

// incrementConsentCheckFailed increments the consent check failed metric if metrics are enabled
func (s *Service) incrementConsentCheckFailed(purpose models.Purpose) {
	if s.metrics != nil {
		s.metrics.IncrementConsentCheckFailed(string(purpose))
	}
}

// incrementActiveConsents updates the active consents gauge when it increases.
func (s *Service) incrementActiveConsents(count float64) {
	if s.metrics != nil {
		s.metrics.IncrementActiveConsents(count)
	}
}

// decrementActiveConsents updates the active consents gauge when it decreases.
func (s *Service) decrementActiveConsents(count float64) {
	if s.metrics != nil {
		s.metrics.DecrementActiveConsents(count)
	}
}

// observeRecordsPerUser records the distribution of consent records per user.
func (s *Service) observeRecordsPerUser(count float64) {
	if s.metrics != nil {
		s.metrics.ObserveRecordsPerUser(count)
	}
}

// logConsentCheck writes a structured log entry for consent checks when logging is enabled.
func (s *Service) logConsentCheck(ctx context.Context, level slog.Level, msg string, userID id.UserID, purpose models.Purpose, state string) {
	if s.logger == nil {
		return
	}
	s.logger.Log(ctx, level, msg,
		"user_id", userID.String(),
		"purpose", purpose,
		"state", state,
	)
}

// consentCheckOutcome encapsulates the result of a consent check for unified recording.
// Invariant: passed=true requires decision=AuditDecisionGranted; passed=false requires decision=AuditDecisionDenied
type consentCheckOutcome struct {
	passed   bool
	status   *models.Status // nil means consent not found ("missing")
	decision string         // models.AuditDecisionGranted or models.AuditDecisionDenied
}

// statusState returns the state string for logging. Returns "missing" if status is nil.
func (o consentCheckOutcome) statusState() string {
	if o.status == nil {
		return "missing"
	}
	return string(*o.status)
}

var (
	statusRevoked  = models.StatusRevoked
	statusExpired  = models.StatusExpired
	statusActive   = models.StatusActive
	outcomeMissing = consentCheckOutcome{passed: false, status: nil, decision: models.AuditDecisionDenied}
	outcomeRevoked = consentCheckOutcome{passed: false, status: &statusRevoked, decision: models.AuditDecisionDenied}
	outcomeExpired = consentCheckOutcome{passed: false, status: &statusExpired, decision: models.AuditDecisionDenied}
	outcomePassed  = consentCheckOutcome{passed: true, status: &statusActive, decision: models.AuditDecisionGranted}
)

// recordConsentCheckOutcome emits audit event, logs, and updates metrics for a consent check.
func (s *Service) recordConsentCheckOutcome(ctx context.Context, userID id.UserID, purpose models.Purpose, outcome consentCheckOutcome) {
	now := requestcontext.Now(ctx)
	action := models.AuditActionConsentCheckPassed
	logLevel := slog.LevelInfo
	logMsg := "consent_check_passed"
	if !outcome.passed {
		action = models.AuditActionConsentCheckFailed
		logLevel = slog.LevelWarn
		logMsg = "consent_check_failed"
	}

	s.emitAudit(ctx, audit.ComplianceEvent{
		UserID:    userID,
		Purpose:   string(purpose),
		Action:    action,
		Decision:  outcome.decision,
		Timestamp: now,
	})
	s.logConsentCheck(ctx, logLevel, logMsg, userID, purpose, outcome.statusState())
	if outcome.passed {
		s.metrics.IncrementConsentCheckPassed(string(purpose))
	} else {
		s.metrics.IncrementConsentCheckFailed(string(purpose))
	}
}
