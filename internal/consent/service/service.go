package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"id-gateway/internal/audit"
	"id-gateway/internal/consent/models"
	"id-gateway/internal/platform/metrics"
	pkgerrors "id-gateway/pkg/domain-errors"
)

type Store interface {
	Save(ctx context.Context, consent *models.Record) error
	FindByUserAndPurpose(ctx context.Context, userID string, purpose models.Purpose) (*models.Record, error)
	ListByUser(ctx context.Context, userID string, filter *models.RecordFilter) ([]*models.Record, error)
	Update(ctx context.Context, consent *models.Record) error
	RevokeByUserAndPurpose(ctx context.Context, userID string, purpose models.Purpose, revokedAt time.Time) (*models.Record, error)
	DeleteByUser(ctx context.Context, userID string) error
}

// Service persists consent decisions and enforces lifecycle rules per PRD-002.
type Service struct {
	store   Store
	auditor *audit.Publisher
	metrics *metrics.Metrics
	logger  *slog.Logger
	ttl     time.Duration
}

func NewService(store Store, auditor *audit.Publisher) *Service {
	svc := &Service{
		store:   store,
		auditor: auditor,
		logger:  slog.Default(),
		ttl:     365 * 24 * time.Hour, // TODO: add to config
	}
	return svc
}

// WithMetrics sets the metrics instance for the service
func WithMetrics(m *metrics.Metrics) func(*Service) {
	return func(s *Service) {
		s.metrics = m
	}
}

// WithLogger sets the logger instance for the service.
func WithLogger(logger *slog.Logger) func(*Service) {
	return func(s *Service) {
		s.logger = logger
	}
}

func (s *Service) Grant(ctx context.Context, userID string, purposes []models.Purpose) ([]*models.Record, error) {
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
	return granted, nil
}

func (s *Service) upsertGrant(ctx context.Context, userID string, purpose models.Purpose) (*models.Record, error) {
	now := time.Now()
	expiry := now.Add(s.ttl)
	existing, err := s.store.FindByUserAndPurpose(ctx, userID, purpose)
	if err != nil {
		return nil, pkgerrors.Wrap(pkgerrors.CodeInternal, "failed to read consent", err)
	}

	if existing != nil && existing.IsActive(now) {
		existing.GrantedAt = now
		existing.ExpiresAt = &expiry
		existing.RevokedAt = nil
		if err := s.store.Update(ctx, existing); err != nil {
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
		return existing, nil
	}

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

func (s *Service) Revoke(ctx context.Context, userID string, purposes []models.Purpose) ([]*models.Record, error) {
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
			return nil, pkgerrors.Wrap(pkgerrors.CodeInternal, "failed to read consent", err)
		}
		if record == nil || record.RevokedAt != nil {
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
	return revoked, nil
}

func (s *Service) List(ctx context.Context, userID string, filter *models.RecordFilter) ([]*models.ConsentWithStatus, error) {
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

	return result, nil
}

func (s *Service) Require(ctx context.Context, userID string, purpose models.Purpose) error {
	if userID == "" {
		return pkgerrors.New(pkgerrors.CodeUnauthorized, "missing user context")
	}
	if !purpose.IsValid() {
		return pkgerrors.New(pkgerrors.CodeBadRequest, fmt.Sprintf("invalid purpose: %s", purpose))
	}

	record, err := s.store.FindByUserAndPurpose(ctx, userID, purpose)
	if err != nil {
		return pkgerrors.Wrap(pkgerrors.CodeInternal, "failed to read consent", err)
	}
	now := time.Now()
	if record == nil {
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
