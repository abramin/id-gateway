package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	consentmetrics "credo/internal/consent/metrics"
	"credo/internal/consent/models"
	id "credo/pkg/domain"
	pkgerrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	auditpublisher "credo/pkg/platform/audit/publisher"
	"credo/pkg/platform/middleware/admin"
	"credo/pkg/platform/sentinel"
	platformsync "credo/pkg/platform/sync"
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
	DeleteByUser(ctx context.Context, userID id.UserID) error
	Execute(ctx context.Context, scope models.ConsentScope, validate func(*models.Record) error, mutate func(*models.Record)) (*models.Record, error)
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
	auditor                *auditpublisher.Publisher
	metrics                *consentmetrics.Metrics
	logger                 *slog.Logger
	consentTTL             time.Duration
	grantIdempotencyWindow time.Duration
	reGrantCooldown        time.Duration
}

// New constructs a consent service with defaults applied.
func New(store Store, auditor *auditpublisher.Publisher, logger *slog.Logger, opts ...Option) *Service {
	svc := &Service{
		store:                  store,
		tx:                     &shardedConsentTx{mu: platformsync.NewShardedMutex(), store: store},
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
	for _, purpose := range purposes {
		if !purpose.IsValid() {
			return nil, pkgerrors.New(pkgerrors.CodeBadRequest, "invalid purpose")
		}
	}

	var (
		granted []*models.Record
		effects []*grantEffect
	)
	// Wrap multi-purpose grant in transaction to ensure atomicity per AGENTS.md
	// Add user ID to context for sharded locking
	txCtx := context.WithValue(ctx, txUserKeyCtx, userID.String())
	txErr := s.tx.RunInTx(txCtx, func(txStore Store) error {
		for _, purpose := range purposes {
			scope, err := models.NewConsentScope(userID, purpose)
			if err != nil {
				return pkgerrors.New(pkgerrors.CodeBadRequest, "invalid consent scope")
			}
			record, effect, err := s.upsertGrantTx(ctx, txStore, scope)
			if err != nil {
				return err
			}
			granted = append(granted, record)
			if effect != nil {
				effects = append(effects, effect)
			}
		}
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}

	for _, effect := range effects {
		s.emitGrantAudit(ctx, effect.record.UserID, effect.record.Purpose, effect.timestamp)
		s.incrementConsentsGranted(effect.record.Purpose)
		if !effect.wasActive {
			s.incrementActiveConsents(1)
		}
	}

	return granted, nil
}

type grantEffect struct {
	record    *models.Record
	wasActive bool
	timestamp time.Time
}

func (s *Service) upsertGrantTx(ctx context.Context, txStore Store, scope models.ConsentScope) (*models.Record, *grantEffect, error) {
	now := requestcontext.Now(ctx)
	for attempt := 0; attempt < 2; attempt++ {
		var (
			wasActive bool
			changed   bool
			updated   models.Record
		)

		record, err := txStore.Execute(ctx, scope,
			func(existing *models.Record) error {
				wasActive = existing.IsActive(now)
				if wasActive && now.Sub(existing.GrantedAt) < s.grantIdempotencyWindow {
					changed = false
					return nil
				}

				// Security: prevent rapid revoke→grant cycles
				// If consent was recently revoked, enforce cooldown before allowing re-grant
				if !existing.CanReGrant(now, s.reGrantCooldown) {
					return pkgerrors.New(pkgerrors.CodeBadRequest,
						fmt.Sprintf("consent was recently revoked; please wait before re-granting (cooldown: %v)", s.reGrantCooldown))
				}

				var err error
				updated, err = existing.RenewAt(now, s.consentTTL)
				if err != nil {
					return err
				}
				changed = true
				return nil
			},
			func(existing *models.Record) {
				if !changed {
					return
				}
				*existing = updated
			},
		)
		if err == nil {
			if !changed {
				return record, nil, nil
			}
			return record, &grantEffect{record: record, wasActive: wasActive, timestamp: now}, nil
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

// createGrantTx creates a new consent record.
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
	s.emitAudit(ctx, audit.Event{
		UserID:    userID,
		Purpose:   string(purpose),
		Action:    models.AuditActionConsentGranted,
		Decision:  models.AuditDecisionGranted,
		Reason:    models.AuditReasonUserInitiated,
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
	for _, purpose := range purposes {
		if !purpose.IsValid() {
			return nil, pkgerrors.New(pkgerrors.CodeBadRequest, "invalid purpose")
		}
	}

	var revoked []*models.Record
	now := requestcontext.Now(ctx)

	// Wrap multi-purpose revoke in transaction to ensure atomicity
	// Add user ID to context for sharded locking
	txCtx := context.WithValue(ctx, txUserKeyCtx, userID.String())
	txErr := s.tx.RunInTx(txCtx, func(txStore Store) error {
		for _, purpose := range purposes {
			scope, err := models.NewConsentScope(userID, purpose)
			if err != nil {
				return pkgerrors.New(pkgerrors.CodeBadRequest, "invalid consent scope")
			}
			var (
				changed bool
				updated models.Record
			)
			record, err := txStore.Execute(ctx, scope,
				func(existing *models.Record) error {
					// Guard: skip if not eligible for revocation (already revoked or expired)
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
				func(existing *models.Record) {
					if !changed {
						return
					}
					*existing = updated
				},
			)
			if errors.Is(err, sentinel.ErrNotFound) {
				// Can't revoke what doesn't exist - skip silently
				continue
			}
			if err != nil {
				var domainErr *pkgerrors.Error
				if errors.As(err, &domainErr) {
					return err
				}
				return pkgerrors.Wrap(err, pkgerrors.CodeInternal, "failed to revoke consent")
			}

			if !changed {
				continue
			}
			revoked = append(revoked, record)
		}
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}

	for _, record := range revoked {
		s.emitAudit(ctx, audit.Event{
			UserID:    userID,
			Purpose:   string(record.Purpose),
			Action:    models.AuditActionConsentRevoked,
			Decision:  models.AuditDecisionRevoked,
			Reason:    models.AuditReasonUserInitiated,
			Timestamp: now,
		})
		s.incrementConsentsRevoked(record.Purpose)
		s.decrementActiveConsents(1)
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
	// Add user ID to context for sharded locking
	txCtx := context.WithValue(ctx, txUserKeyCtx, userID.String())
	txErr := s.tx.RunInTx(txCtx, func(txStore Store) error {
		records, err := txStore.ListByUser(ctx, userID, nil)
		if err != nil {
			return pkgerrors.Wrap(err, pkgerrors.CodeInternal, "failed to list consents for revocation")
		}

		for _, record := range records {
			scope, err := models.NewConsentScope(userID, record.Purpose)
			if err != nil {
				return pkgerrors.New(pkgerrors.CodeBadRequest, "invalid consent scope")
			}
			var (
				changed bool
				updated models.Record
			)
			_, err = txStore.Execute(ctx, scope,
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
				func(existing *models.Record) {
					if !changed {
						return
					}
					*existing = updated
				},
			)
			if errors.Is(err, sentinel.ErrNotFound) {
				continue
			}
			if err != nil {
				var domainErr *pkgerrors.Error
				if errors.As(err, &domainErr) {
					return err
				}
				return pkgerrors.Wrap(err, pkgerrors.CodeInternal, "failed to revoke consent")
			}
			if changed {
				revokedCount++
			}
		}

		return nil
	})
	if txErr != nil {
		return 0, txErr
	}

	if revokedCount > 0 {
		// Include admin actor ID for audit attribution if present
		actorID := admin.GetAdminActorID(ctx)
		s.emitAudit(ctx, audit.Event{
			UserID:    userID,
			Action:    models.AuditActionConsentRevoked,
			Decision:  models.AuditDecisionRevoked,
			Reason:    "bulk_revocation",
			Timestamp: now,
			ActorID:   actorID,
		})
		s.decrementActiveConsents(float64(revokedCount))
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
	if err := s.store.DeleteByUser(ctx, userID); err != nil {
		return pkgerrors.Wrap(err, pkgerrors.CodeInternal, "failed to delete all consents")
	}

	// Include admin actor ID for audit attribution if present
	actorID := admin.GetAdminActorID(ctx)
	s.emitAudit(ctx, audit.Event{
		UserID:    userID,
		Action:    models.AuditActionConsentDeleted,
		Decision:  models.AuditDecisionDeleted,
		Reason:    "bulk_deletion",
		Timestamp: requestcontext.Now(ctx),
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
	s.observeRecordsPerUser(float64(len(records)))

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

func (s *Service) emitAudit(ctx context.Context, event audit.Event) {
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
	state    models.ConsentCheckState
	decision string // models.AuditDecisionGranted or models.AuditDecisionDenied
}

var (
	outcomeMissing = consentCheckOutcome{passed: false, state: models.ConsentCheckStateMissing, decision: models.AuditDecisionDenied}
	outcomeRevoked = consentCheckOutcome{passed: false, state: models.ConsentCheckStateRevoked, decision: models.AuditDecisionDenied}
	outcomeExpired = consentCheckOutcome{passed: false, state: models.ConsentCheckStateExpired, decision: models.AuditDecisionDenied}
	outcomePassed  = consentCheckOutcome{passed: true, state: models.ConsentCheckStateActive, decision: models.AuditDecisionGranted}
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

	s.emitAudit(ctx, audit.Event{
		UserID:    userID,
		Purpose:   string(purpose),
		Action:    action,
		Decision:  outcome.decision,
		Reason:    models.AuditReasonUserInitiated,
		Timestamp: now,
	})
	s.logConsentCheck(ctx, logLevel, logMsg, userID, purpose, outcome.state.String())
	if outcome.passed {
		s.incrementConsentCheckPassed(purpose)
	} else {
		s.incrementConsentCheckFailed(purpose)
	}
}
