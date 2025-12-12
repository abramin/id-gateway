package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"credo/internal/audit"
	"credo/internal/consent/models"
	"credo/internal/consent/store"
	"credo/internal/platform/metrics"
	pkgerrors "credo/pkg/domain-errors"
)

// Store defines the persistence interface for consent records.
// Error Contract:
// - FindByUserAndPurpose returns store.ErrNotFound when no record exists
// - Other methods return nil on success or wrapped errors on failure
type Store interface {
	Save(ctx context.Context, consent *models.Record) error
	FindByUserAndPurpose(ctx context.Context, userID string, purpose models.Purpose) (*models.Record, error)
	ListByUser(ctx context.Context, userID string, filter *models.RecordFilter) ([]*models.Record, error)
	Update(ctx context.Context, consent *models.Record) error
	RevokeByUserAndPurpose(ctx context.Context, userID string, purpose models.Purpose, revokedAt time.Time) (*models.Record, error)
	DeleteByUser(ctx context.Context, userID string) error
}

type Option func(*Service)

const (
	defaultConsentTTL             = 365 * 24 * time.Hour // 1 year
	defaultGrantIdempotencyWindow = 1 * time.Second
)

// Service persists consent decisions and enforces lifecycle rules per PRD-002.
type Service struct {
	store                  Store
	auditor                *audit.Publisher
	metrics                *metrics.Metrics
	logger                 *slog.Logger
	consentTTL             time.Duration
	grantIdempotencyWindow time.Duration
}

func NewService(store Store, auditor *audit.Publisher, logger *slog.Logger, opts ...Option) *Service {
	svc := &Service{
		store:                  store,
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

func (s *Service) Grant(ctx context.Context, userID string, purposes []models.Purpose) (*models.GrantResponse, error) {
	if userID == "" {
		return nil, pkgerrors.New(pkgerrors.CodeUnauthorized, "missing user context")
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
	for _, purpose := range purposes {
		record, err := s.upsertGrant(ctx, userID, purpose)
		if err != nil {
			return nil, err
		}
		granted = append(granted, record)
	}

	now := time.Now()
	return &models.GrantResponse{
		Granted: s.formatGrantResponses(granted, now),
		Message: formatActionMessage("Consent granted for %d purpose", len(granted)),
	}, nil
}

func (s *Service) upsertGrant(ctx context.Context, userID string, purpose models.Purpose) (*models.Record, error) {
	now := time.Now()
	expiry := now.Add(s.consentTTL)
	existing, err := s.store.FindByUserAndPurpose(ctx, userID, purpose)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, pkgerrors.Wrap(pkgerrors.CodeInternal, "failed to read consent", err)
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
		if err := s.store.Update(ctx, &updated); err != nil {
			return nil, pkgerrors.Wrap(pkgerrors.CodeInternal, "failed to renew consent", err)
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

	// First-time consent grant - create new record
	record := &models.Record{
		ID:        fmt.Sprintf("consent_%s", uuid.New().String()),
		UserID:    userID,
		Purpose:   purpose,
		GrantedAt: now,
		ExpiresAt: &expiry,
	}
	if err := s.store.Save(ctx, record); err != nil {
		return nil, pkgerrors.Wrap(pkgerrors.CodeInternal, "failed to save consent", err)
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

func (s *Service) Revoke(ctx context.Context, userID string, purposes []models.Purpose) (*models.RevokeResponse, error) {
	if userID == "" {
		return nil, pkgerrors.New(pkgerrors.CodeUnauthorized, "missing user context")
	}
	for _, purpose := range purposes {
		if !purpose.IsValid() {
			return nil, pkgerrors.New(pkgerrors.CodeBadRequest, fmt.Sprintf("invalid purpose: %s", purpose))
		}
	}

	var revoked []*models.Record
	for _, purpose := range purposes {
		record, err := s.store.FindByUserAndPurpose(ctx, userID, purpose)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				// Can't revoke what doesn't exist - skip silently
				continue
			}
			return nil, pkgerrors.Wrap(pkgerrors.CodeInternal, "failed to read consent", err)
		}
		if record.RevokedAt != nil {
			continue
		}
		if record.ExpiresAt != nil && record.ExpiresAt.Before(time.Now()) {
			continue
		}
		now := time.Now()
		revokedRecord, err := s.store.RevokeByUserAndPurpose(ctx, userID, record.Purpose, now)
		if err != nil {
			return nil, pkgerrors.Wrap(pkgerrors.CodeInternal, "failed to revoke consent", err)
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

	return &models.RevokeResponse{
		Revoked: s.formatRevokeResponses(revoked),
		Message: formatActionMessage("Consent revoked for %d purpose", len(revoked)),
	}, nil
}

func (s *Service) List(ctx context.Context, userID string, filter *models.RecordFilter) (*models.ListResponse, error) {
	if userID == "" {
		return nil, pkgerrors.New(pkgerrors.CodeUnauthorized, "missing user context")
	}

	records, err := s.store.ListByUser(ctx, userID, filter)
	if err != nil {
		return nil, pkgerrors.Wrap(pkgerrors.CodeInternal, "failed to list consents", err)
	}

	now := time.Now()
	var result []*models.ConsentWithStatus

	for _, record := range records {
		result = append(result, &models.ConsentWithStatus{
			Consent: models.Consent{
				ID:        record.ID,
				Purpose:   record.Purpose,
				GrantedAt: record.GrantedAt,
				ExpiresAt: record.ExpiresAt,
				RevokedAt: record.RevokedAt,
			},
			Status: record.ComputeStatus(now),
		})
	}

	return &models.ListResponse{Consents: result}, nil
}

func (s *Service) Require(ctx context.Context, userID string, purpose models.Purpose) error {
	if userID == "" {
		return pkgerrors.New(pkgerrors.CodeUnauthorized, "missing user context")
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
		return pkgerrors.Wrap(pkgerrors.CodeInternal, "failed to read consent", err)
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
	_ = s.auditor.Emit(ctx, event)
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

func (s *Service) logConsentCheck(ctx context.Context, level slog.Level, msg string, userID string, purpose models.Purpose, state string) {
	if s.logger == nil {
		return
	}
	s.logger.Log(ctx, level, msg,
		"user_id", userID,
		"purpose", purpose,
		"state", state,
	)
}

// formatGrantResponses transforms domain records to Grant response DTOs
func (s *Service) formatGrantResponses(records []*models.Record, now time.Time) []*models.Grant {
	var resp []*models.Grant
	for _, record := range records {
		resp = append(resp, &models.Grant{
			Purpose:   record.Purpose,
			GrantedAt: record.GrantedAt,
			ExpiresAt: record.ExpiresAt,
			Status:    record.ComputeStatus(now),
		})
	}
	return resp
}

// formatRevokeResponses transforms domain records to Revoked response DTOs
func (s *Service) formatRevokeResponses(revoked []*models.Record) []*models.Revoked {
	var resp []*models.Revoked
	for _, record := range revoked {
		resp = append(resp, &models.Revoked{
			Purpose:   record.Purpose,
			RevokedAt: *record.RevokedAt,
			Status:    record.ComputeStatus(time.Now()),
		})
	}
	return resp
}

// formatActionMessage creates user-facing messages with proper pluralization
func formatActionMessage(template string, count int) string {
	return fmt.Sprintf(template+"%s", count, pluralSuffix(count))
}

// pluralSuffix returns "s" for counts != 1, empty string otherwise
func pluralSuffix(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}
