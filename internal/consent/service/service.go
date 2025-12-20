package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"credo/internal/audit"
	"credo/internal/consent/models"
	"credo/internal/consent/store"
	"credo/internal/platform/metrics"
	id "credo/pkg/domain"
	pkgerrors "credo/pkg/domain-errors"
)

// shardedConsentTx provides fine-grained locking using sharded mutexes.
// Instead of a single global lock, operations are distributed across N shards
// based on a hash of the user ID, reducing contention under concurrent load.
const numConsentShards = 32

// defaultConsentTxTimeout is the maximum duration for a consent transaction.
const defaultConsentTxTimeout = 5 * time.Second

type shardedConsentTx struct {
	shards  [numConsentShards]sync.Mutex
	store   Store
	timeout time.Duration
}

func (t *shardedConsentTx) RunInTx(ctx context.Context, fn func(store Store) error) error {
	// Check if context is already cancelled
	if err := ctx.Err(); err != nil {
		return pkgerrors.Wrap(err, pkgerrors.CodeTimeout, "transaction aborted: context cancelled")
	}

	// Apply timeout if not already set
	timeout := t.timeout
	if timeout == 0 {
		timeout = defaultConsentTxTimeout
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	shard := t.selectShard(ctx)
	t.shards[shard].Lock()
	defer t.shards[shard].Unlock()

	// Check again after acquiring lock
	if err := ctx.Err(); err != nil {
		return pkgerrors.Wrap(err, pkgerrors.CodeTimeout, "transaction aborted: context cancelled")
	}

	return fn(t.store)
}

// selectShard picks a shard based on user ID from context, or defaults to shard 0.
func (t *shardedConsentTx) selectShard(ctx context.Context) int {
	if userID, ok := ctx.Value(txUserKeyCtx).(string); ok && userID != "" {
		return int(hashConsentString(userID) % numConsentShards)
	}
	return 0
}

func hashConsentString(s string) uint32 {
	var h uint32
	for i := 0; i < len(s); i++ {
		h = h*31 + uint32(s[i])
	}
	return h
}

type txUserKey struct{}

var txUserKeyCtx = txUserKey{}

// Store defines the persistence interface for consent records.
// Error Contract:
// - FindByUserAndPurpose returns store.ErrNotFound when no record exists
// - Other methods return nil on success or wrapped errors on failure
type Store interface {
	Save(ctx context.Context, consent *models.Record) error
	FindByUserAndPurpose(ctx context.Context, userID id.UserID, purpose models.Purpose) (*models.Record, error)
	ListByUser(ctx context.Context, userID id.UserID, filter *models.RecordFilter) ([]*models.Record, error)
	Update(ctx context.Context, consent *models.Record) error
	RevokeByUserAndPurpose(ctx context.Context, userID id.UserID, purpose models.Purpose, revokedAt time.Time) (*models.Record, error)
	RevokeAllByUser(ctx context.Context, userID id.UserID, revokedAt time.Time) (int, error)
	DeleteByUser(ctx context.Context, userID id.UserID) error
}

type Option func(*Service)

const (
	defaultConsentTTL             = 365 * 24 * time.Hour // 1 year
	defaultGrantIdempotencyWindow = 5 * time.Minute
)

// Service persists consent decisions and enforces lifecycle rules per PRD-002.
type Service struct {
	store                  Store
	tx                     ConsentStoreTx
	auditor                *audit.Publisher
	metrics                *metrics.Metrics
	logger                 *slog.Logger
	consentTTL             time.Duration
	grantIdempotencyWindow time.Duration
}

func NewService(store Store, auditor *audit.Publisher, logger *slog.Logger, opts ...Option) *Service {
	svc := &Service{
		store:                  store,
		tx:                     &shardedConsentTx{store: store},
		auditor:                auditor,
		logger:                 logger,
		consentTTL:             defaultConsentTTL,
		grantIdempotencyWindow: defaultGrantIdempotencyWindow,
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
	return svc
}

// WithTx sets a custom transaction provider for the service.
func WithTx(tx ConsentStoreTx) Option {
	return func(s *Service) {
		s.tx = tx
	}
}

// WithMetrics sets the metrics instance for the service
func WithMetrics(m *metrics.Metrics) Option {
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
// If not set or set to zero/negative, defaults to 1 second.
func WithGrantWindow(window time.Duration) Option {
	return func(s *Service) {
		if window > 0 {
			s.grantIdempotencyWindow = window
		}
	}
}

// Grant grants consent for the specified purposes.
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
			return nil, pkgerrors.New(pkgerrors.CodeBadRequest, fmt.Sprintf("invalid purpose: %s", purpose))
		}
	}

	var granted []*models.Record
	// Wrap multi-purpose grant in transaction to ensure atomicity per AGENTS.md
	// Add user ID to context for sharded locking
	txCtx := context.WithValue(ctx, txUserKeyCtx, userID.String())
	txErr := s.tx.RunInTx(txCtx, func(txStore Store) error {
		for _, purpose := range purposes {
			record, err := s.upsertGrantTx(ctx, txStore, userID, purpose)
			if err != nil {
				return err
			}
			granted = append(granted, record)
		}
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}

	return granted, nil
}

func (s *Service) upsertGrantTx(ctx context.Context, txStore Store, userID id.UserID, purpose models.Purpose) (*models.Record, error) {
	now := time.Now()
	expiry := now.Add(s.consentTTL)
	existing, err := txStore.FindByUserAndPurpose(ctx, userID, purpose)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, pkgerrors.Wrap(err, pkgerrors.CodeInternal, "failed to read consent")
	}

	// Reuse existing consent record (active, expired, or revoked) to maintain clean DB
	// History is tracked via audit log
	if err == nil && existing != nil {
		wasActive := existing.IsActive(now)

		// Idempotent within configured window: skip update if recently granted
		// This prevents audit noise from rapid repeated requests while still allowing periodic TTL extension
		if wasActive && now.Sub(existing.GrantedAt) < s.grantIdempotencyWindow {
			return existing, nil
		}

		updated := *existing
		updated.GrantedAt = now
		updated.ExpiresAt = &expiry
		updated.RevokedAt = nil
		if err := txStore.Update(ctx, &updated); err != nil {
			return nil, pkgerrors.Wrap(err, pkgerrors.CodeInternal, "failed to renew consent")
		}
		s.emitAudit(ctx, audit.Event{
			UserID:    userID,
			Purpose:   string(purpose),
			Action:    models.AuditActionConsentGranted,
			Decision:  models.AuditDecisionGranted,
			Reason:    models.AuditReasonUserInitiated,
			Timestamp: now,
		})
		s.incrementConsentsGranted(purpose)
		if !wasActive {
			s.incrementActiveConsents(1)
		}
		return &updated, nil
	}

	// First-time consent grant - create new record using constructor
	record, err := models.NewRecord(
		id.ConsentID(uuid.New()),
		userID,
		purpose,
		now,
		&expiry,
	)
	if err != nil {
		return nil, pkgerrors.Wrap(err, pkgerrors.CodeInternal, "failed to create consent record")
	}
	if err := txStore.Save(ctx, record); err != nil {
		return nil, pkgerrors.Wrap(err, pkgerrors.CodeInternal, "failed to save consent")
	}
	s.emitAudit(ctx, audit.Event{
		UserID:    userID,
		Purpose:   string(purpose),
		Action:    models.AuditActionConsentGranted,
		Decision:  models.AuditDecisionGranted,
		Reason:    models.AuditReasonUserInitiated,
		Timestamp: now,
	})
	s.incrementConsentsGranted(purpose)
	s.incrementActiveConsents(1)
	return record, nil
}

// Revoke revokes consent for the specified purposes.
// Returns the revoked records (domain objects), not HTTP response DTOs.
func (s *Service) Revoke(ctx context.Context, userID id.UserID, purposes []models.Purpose) ([]*models.Record, error) {
	if userID.IsNil() {
		return nil, pkgerrors.New(pkgerrors.CodeUnauthorized, "user ID required")
	}
	for _, purpose := range purposes {
		if !purpose.IsValid() {
			return nil, pkgerrors.New(pkgerrors.CodeBadRequest, fmt.Sprintf("invalid purpose: %s", purpose))
		}
	}

	var revoked []*models.Record
	// Wrap multi-purpose revoke in transaction to ensure atomicity per AGENTS.md
	// Add user ID to context for sharded locking
	txCtx := context.WithValue(ctx, txUserKeyCtx, userID.String())
	txErr := s.tx.RunInTx(txCtx, func(txStore Store) error {
		for _, purpose := range purposes {
			record, err := txStore.FindByUserAndPurpose(ctx, userID, purpose)
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					// Can't revoke what doesn't exist - skip silently
					continue
				}
				return pkgerrors.Wrap(err, pkgerrors.CodeInternal, "failed to read consent")
			}
			if record.RevokedAt != nil {
				continue
			}
			if record.ExpiresAt != nil && record.ExpiresAt.Before(time.Now()) {
				// Expired consents are effectively inactive; skip to keep revoke idempotent.
				continue
			}
			now := time.Now()
			revokedRecord, err := txStore.RevokeByUserAndPurpose(ctx, userID, record.Purpose, now)
			if err != nil {
				return pkgerrors.Wrap(err, pkgerrors.CodeInternal, "failed to revoke consent")
			}
			if revokedRecord.RevokedAt == nil {
				revokedRecord.RevokedAt = &now
			}
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
			revoked = append(revoked, revokedRecord)
		}
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}

	return revoked, nil
}

// RevokeAll revokes all active consents for a user.
// Intended for test cleanup and administrative purposes.
// Returns the count of revoked consents.
func (s *Service) RevokeAll(ctx context.Context, userID id.UserID) (int, error) {
	if userID.IsNil() {
		return 0, pkgerrors.New(pkgerrors.CodeBadRequest, "user ID required")
	}
	now := time.Now()
	count, err := s.store.RevokeAllByUser(ctx, userID, now)
	if err != nil {
		return 0, pkgerrors.Wrap(err, pkgerrors.CodeInternal, "failed to revoke all consents")
	}

	if count > 0 {
		s.emitAudit(ctx, audit.Event{
			UserID:    userID,
			Action:    models.AuditActionConsentRevoked,
			Decision:  models.AuditDecisionRevoked,
			Reason:    "bulk_revocation",
			Timestamp: now,
		})
		s.decrementActiveConsents(float64(count))
	}

	return count, nil
}

// DeleteAll removes all consent records for a user.
// Intended for GDPR right to erasure and test cleanup.
func (s *Service) DeleteAll(ctx context.Context, userID id.UserID) error {
	if userID.IsNil() {
		return pkgerrors.New(pkgerrors.CodeBadRequest, "user ID required")
	}
	if err := s.store.DeleteByUser(ctx, userID); err != nil {
		return pkgerrors.Wrap(err, pkgerrors.CodeInternal, "failed to delete all consents")
	}

	s.emitAudit(ctx, audit.Event{
		UserID:    userID,
		Action:    "consent_deleted",
		Decision:  "deleted",
		Reason:    "bulk_deletion",
		Timestamp: time.Now(),
	})

	return nil
}

// List returns all consent records for a user.
// Returns domain objects, not HTTP response DTOs.
func (s *Service) List(ctx context.Context, userID id.UserID, filter *models.RecordFilter) ([]*models.Record, error) {
	if userID.IsNil() {
		return nil, pkgerrors.New(pkgerrors.CodeUnauthorized, "user ID required")
	}
	records, err := s.store.ListByUser(ctx, userID, filter)
	if err != nil {
		return nil, pkgerrors.Wrap(err, pkgerrors.CodeInternal, "failed to list consents")
	}

	return records, nil
}

func (s *Service) Require(ctx context.Context, userID id.UserID, purpose models.Purpose) error {
	if userID.IsNil() {
		return pkgerrors.New(pkgerrors.CodeUnauthorized, "user ID required")
	}
	if !purpose.IsValid() {
		return pkgerrors.New(pkgerrors.CodeBadRequest, fmt.Sprintf("invalid purpose: %s", purpose))
	}

	record, err := s.store.FindByUserAndPurpose(ctx, userID, purpose)
	now := time.Now()
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Not found = missing consent
			s.emitAudit(ctx, audit.Event{
				UserID:    userID,
				Purpose:   string(purpose),
				Action:    models.AuditActionConsentCheckFailed,
				Decision:  models.AuditDecisionDenied,
				Reason:    models.AuditReasonUserInitiated,
				Timestamp: now,
			})
			s.logConsentCheck(ctx, slog.LevelWarn, "consent_check_failed", userID, purpose, "missing")
			s.incrementConsentCheckFailed(purpose)
			return pkgerrors.New(pkgerrors.CodeMissingConsent, "consent not granted for required purpose")
		}
		return pkgerrors.Wrap(err, pkgerrors.CodeInternal, "failed to read consent")
	}
	if record.RevokedAt != nil {
		s.emitAudit(ctx, audit.Event{
			UserID:    userID,
			Purpose:   string(purpose),
			Action:    models.AuditActionConsentCheckFailed,
			Decision:  models.AuditDecisionDenied,
			Reason:    models.AuditReasonUserInitiated,
			Timestamp: now,
		})
		s.logConsentCheck(ctx, slog.LevelWarn, "consent_check_failed", userID, purpose, "revoked")
		s.incrementConsentCheckFailed(purpose)
		return pkgerrors.New(pkgerrors.CodeInvalidConsent, "consent revoked")
	}
	if record.ExpiresAt != nil && record.ExpiresAt.Before(now) {
		s.emitAudit(ctx, audit.Event{
			UserID:    userID,
			Purpose:   string(purpose),
			Action:    models.AuditActionConsentCheckFailed,
			Decision:  models.AuditDecisionDenied,
			Reason:    models.AuditReasonUserInitiated,
			Timestamp: now,
		})
		s.logConsentCheck(ctx, slog.LevelWarn, "consent_check_failed", userID, purpose, "expired")
		s.incrementConsentCheckFailed(purpose)
		return pkgerrors.New(pkgerrors.CodeInvalidConsent, "consent expired")
	}
	s.emitAudit(ctx, audit.Event{
		UserID:    userID,
		Purpose:   string(purpose),
		Action:    models.AuditActionConsentCheckPassed,
		Decision:  models.AuditDecisionGranted,
		Reason:    models.AuditReasonUserInitiated,
		Timestamp: now,
	})
	s.logConsentCheck(ctx, slog.LevelInfo, "consent_check_passed", userID, purpose, "active")
	s.incrementConsentCheckPassed(purpose)
	return nil
}

func (s *Service) emitAudit(ctx context.Context, event audit.Event) {
	if s.auditor == nil {
		return
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
		s.metrics.IncrementActiveConsentsPerUser(count)
	}
}

// decrementActiveConsents updates the active consents gauge when it decreases.
func (s *Service) decrementActiveConsents(count float64) {
	if s.metrics != nil {
		s.metrics.DecrementActiveConsentsPerUser(count)
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
