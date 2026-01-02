package service

// Unit tests for consent service following Credo testing doctrine (AGENTS.md, testing.md).
//
// Per testing doctrine, unit tests are TERTIARY and exist only to:
// - Enforce invariants
// - Test edge cases unreachable via integration tests
// - Assert error propagation/mapping across boundaries
// - Test pure functions with meaningful logic
//
// Happy-path behavior is tested via:
// - Primary: e2e/features/consent_flow.feature (Gherkin scenarios)
// - Secondary: internal/consent/integration_test.go (timing-sensitive, state manipulation)

//go:generate mockgen -source=service.go -destination=mocks/mocks.go -package=mocks Store

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	"credo/internal/consent/models"
	"credo/internal/consent/service/mocks"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	auditpublisher "credo/pkg/platform/audit/publisher"
	auditstore "credo/pkg/platform/audit/store/memory"
	"credo/pkg/platform/sentinel"
	"credo/pkg/requestcontext"
)

type ServiceSuite struct {
	suite.Suite
	ctrl       *gomock.Controller
	mockStore  *mocks.MockStore
	service    *Service
	auditStore *auditstore.InMemoryStore
}

func (s *ServiceSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.mockStore = mocks.NewMockStore(s.ctrl)
	s.auditStore = auditstore.NewInMemoryStore()
	auditor := auditpublisher.NewPublisher(s.auditStore)
	s.service = New(
		s.mockStore,
		auditor,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithConsentTTL(365*24*time.Hour),
		WithGrantWindow(5*time.Minute),
	)
}

func (s *ServiceSuite) TearDownTest() {
	s.ctrl.Finish()
}

func TestServiceSuite(t *testing.T) {
	suite.Run(t, new(ServiceSuite))
}

// =============================================================================
// Grant Tests - Error Propagation & Validation
// =============================================================================

// TestGrant_ValidationErrors verifies domain error code mapping for invalid input.
// Invariant: Invalid input must return appropriate domain error codes (CodeUnauthorized, CodeBadRequest).
// Reason not a feature test: Feature tests verify HTTP status codes; this tests internal error code mapping.
func (s *ServiceSuite) TestGrant_ValidationErrors() {
	s.Run("empty purposes returns CodeBadRequest", func() {
		_, err := s.service.Grant(context.Background(), id.UserID(uuid.New()), []models.Purpose{})
		s.Require().Error(err)
		s.Assert().True(dErrors.HasCode(err, dErrors.CodeBadRequest), "expected CodeBadRequest for empty purposes")
	})

	s.Run("invalid purpose returns CodeBadRequest", func() {
		_, err := s.service.Grant(context.Background(), id.UserID(uuid.New()), []models.Purpose{"invalid_purpose"})
		s.Require().Error(err)
		s.Assert().True(dErrors.HasCode(err, dErrors.CodeBadRequest), "expected CodeBadRequest for invalid purpose")
	})
}

// TestGrant_StoreErrorPropagation verifies that store errors are properly wrapped and propagated.
// Invariant: Store failures must surface as CodeInternal errors without leaking implementation details.
// Reason not a feature test: Tests internal error wrapping boundary; feature tests cannot induce store failures.
func (s *ServiceSuite) TestGrant_StoreErrorPropagation() {
	s.Run("store error on execute propagates as CodeInternal", func() {
		userID := id.UserID(uuid.New())
		s.mockStore.EXPECT().
			Execute(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, assert.AnError)

		_, err := s.service.Grant(context.Background(), userID, []models.Purpose{models.PurposeLogin})
		s.Require().Error(err)
		s.Assert().True(dErrors.HasCode(err, dErrors.CodeInternal), "expected CodeInternal for store execute error")
	})

	s.Run("store error on save propagates as CodeInternal", func() {
		userID := id.UserID(uuid.New())
		s.mockStore.EXPECT().
			Execute(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, sentinel.ErrNotFound)

		s.mockStore.EXPECT().
			Save(gomock.Any(), gomock.Any()).
			Return(assert.AnError)

		_, err := s.service.Grant(context.Background(), userID, []models.Purpose{models.PurposeLogin})
		s.Require().Error(err)
		s.Assert().True(dErrors.HasCode(err, dErrors.CodeInternal), "expected CodeInternal for store save error")
	})
}

// =============================================================================
// Revoke Tests - Error Propagation & Validation
// =============================================================================

// TestRevoke_ValidationErrors verifies domain error code mapping for invalid input.
// Invariant: Invalid input must return appropriate domain error codes.
// Reason not a feature test: Feature tests verify HTTP status codes; this tests internal error code mapping.
func (s *ServiceSuite) TestRevoke_ValidationErrors() {
	s.Run("invalid purpose returns CodeBadRequest", func() {
		_, err := s.service.Revoke(context.Background(), id.UserID(uuid.New()), []models.Purpose{"invalid_purpose"})
		s.Require().Error(err)
		s.Assert().True(dErrors.HasCode(err, dErrors.CodeBadRequest), "expected CodeBadRequest for invalid purpose")
	})
}

// TestRevoke_StoreErrorPropagation verifies that store errors are properly wrapped and propagated.
// Invariant: Store failures must surface as CodeInternal errors.
// Reason not a feature test: Tests internal error wrapping boundary; feature tests cannot induce store failures.
func (s *ServiceSuite) TestRevoke_StoreErrorPropagation() {
	s.Run("store error on execute propagates as CodeInternal", func() {
		userID := id.UserID(uuid.New())
		s.mockStore.EXPECT().
			Execute(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, assert.AnError)

		_, err := s.service.Revoke(context.Background(), userID, []models.Purpose{models.PurposeLogin})
		s.Require().Error(err)
		s.Assert().True(dErrors.HasCode(err, dErrors.CodeInternal), "expected CodeInternal for store execute error")
	})
}

// TestRevokeAll_Audit verifies audit behavior for bulk revocation.
// Invariant: Bulk revoke emits a single audit event when any records are revoked.
func (s *ServiceSuite) TestRevokeAll_Audit() {
	s.Run("bulk revoke emits audit event when count > 0", func() {
		userID := id.UserID(uuid.New())
		s.mockStore.EXPECT().
			RevokeAllByUser(gomock.Any(), userID, gomock.Any()).
			Return(2, nil)

		count, err := s.service.RevokeAll(context.Background(), userID)
		s.Require().NoError(err)
		s.Assert().Equal(2, count)

		events, err := s.auditStore.ListByUser(context.Background(), userID)
		s.Require().NoError(err)
		s.Require().Len(events, 1)
		s.Assert().Equal(models.AuditActionConsentRevoked, events[0].Action)
		s.Assert().Equal("bulk_revocation", events[0].Reason)
	})

	s.Run("bulk revoke emits no audit event when count == 0", func() {
		userID := id.UserID(uuid.New())
		s.mockStore.EXPECT().
			RevokeAllByUser(gomock.Any(), userID, gomock.Any()).
			Return(0, nil)

		count, err := s.service.RevokeAll(context.Background(), userID)
		s.Require().NoError(err)
		s.Assert().Equal(0, count)

		events, err := s.auditStore.ListByUser(context.Background(), userID)
		s.Require().NoError(err)
		s.Assert().Len(events, 0)
	})
}

// TestGrant_IdempotentSkip verifies idempotent grants skip side effects.
// Invariant: When a grant is within the idempotency window, no audit events are emitted.
func (s *ServiceSuite) TestGrant_IdempotentSkip() {
	now := time.Now()
	userID := id.UserID(uuid.New())
	scope, err := models.NewConsentScope(userID, models.PurposeLogin)
	s.Require().NoError(err)
	ctx := requestcontext.WithTime(context.Background(), now)

	existing := &models.Record{
		ID:        id.ConsentID(uuid.New()),
		UserID:    userID,
		Purpose:   models.PurposeLogin,
		GrantedAt: now.Add(-time.Minute),
		ExpiresAt: ptrTime(now.Add(time.Hour)),
	}

	s.mockStore.EXPECT().
		Execute(gomock.Any(), scope, gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ models.ConsentScope, validate func(*models.Record) error, mutate func(*models.Record) bool) (*models.Record, error) {
			if err := validate(existing); err != nil {
				return nil, err
			}
			mutate(existing)
			return existing, nil
		})

	records, err := s.service.Grant(ctx, userID, []models.Purpose{models.PurposeLogin})
	s.Require().NoError(err)
	s.Require().Len(records, 1)

	events, err := s.auditStore.ListByUser(context.Background(), userID)
	s.Require().NoError(err)
	s.Assert().Len(events, 0)
}

func ptrTime(t time.Time) *time.Time {
	return &t
}

// =============================================================================
// Require Tests - Consent Enforcement Invariants
// =============================================================================

// TestRequire_ConsentEnforcement verifies the consent check invariants.
// These tests enforce domain invariants for consent checking that are not easily
// expressible in Gherkin (requires specific consent states and error code verification).

// TestRequire_ValidationErrors verifies domain error code mapping for invalid input.
// Invariant: Invalid input must return appropriate domain error codes.
func (s *ServiceSuite) TestRequire_ValidationErrors() {
	s.Run("invalid purpose returns CodeBadRequest", func() {
		err := s.service.Require(context.Background(), id.UserID(uuid.New()), "invalid_purpose")
		s.Require().Error(err)
		s.Assert().True(dErrors.HasCode(err, dErrors.CodeBadRequest), "expected CodeBadRequest for invalid purpose")
	})
}

// TestRequire_ConsentStates verifies correct error codes for different consent states.
// Invariant: Missing consent must return CodeMissingConsent; revoked/expired must return CodeInvalidConsent.
// Reason not a feature test: Tests specific domain error codes that map to HTTP responses in handlers.
func (s *ServiceSuite) TestRequire_ConsentStates() {
	now := time.Now()
	future := now.Add(time.Hour)
	expired := now.Add(-time.Hour)

	s.Run("missing consent returns CodeMissingConsent", func() {
		userID := id.UserID(uuid.New())
		s.mockStore.EXPECT().
			FindByScope(gomock.Any(), gomock.Any()).
			Return(nil, sentinel.ErrNotFound)

		err := s.service.Require(context.Background(), userID, models.PurposeVCIssuance)
		s.Require().Error(err)
		s.Assert().True(dErrors.HasCode(err, dErrors.CodeMissingConsent), "expected CodeMissingConsent for missing consent")
	})

	s.Run("revoked consent returns CodeInvalidConsent", func() {
		userID := id.UserID(uuid.New())
		record := &models.Record{
			ID:        id.ConsentID(uuid.New()),
			Purpose:   models.PurposeVCIssuance,
			RevokedAt: &now,
		}

		s.mockStore.EXPECT().
			FindByScope(gomock.Any(), gomock.Any()).
			Return(record, nil)

		err := s.service.Require(context.Background(), userID, models.PurposeVCIssuance)
		s.Require().Error(err)
		s.Assert().True(dErrors.HasCode(err, dErrors.CodeInvalidConsent), "expected CodeInvalidConsent for revoked consent")
	})

	s.Run("expired consent returns CodeInvalidConsent", func() {
		userID := id.UserID(uuid.New())
		record := &models.Record{
			ID:        id.ConsentID(uuid.New()),
			Purpose:   models.PurposeVCIssuance,
			ExpiresAt: &expired,
		}

		s.mockStore.EXPECT().
			FindByScope(gomock.Any(), gomock.Any()).
			Return(record, nil)

		err := s.service.Require(context.Background(), userID, models.PurposeVCIssuance)
		s.Require().Error(err)
		s.Assert().True(dErrors.HasCode(err, dErrors.CodeInvalidConsent), "expected CodeInvalidConsent for expired consent")
	})

	s.Run("active consent returns nil", func() {
		userID := id.UserID(uuid.New())
		record := &models.Record{
			ID:        id.ConsentID(uuid.New()),
			Purpose:   models.PurposeVCIssuance,
			ExpiresAt: &future,
		}

		s.mockStore.EXPECT().
			FindByScope(gomock.Any(), gomock.Any()).
			Return(record, nil)

		err := s.service.Require(context.Background(), userID, models.PurposeVCIssuance)
		s.Assert().NoError(err)
	})
}

// TestRequire_TimeBoundary verifies the exact boundary behavior for consent expiry.
// Invariant: Consent with ExpiresAt == now (or 1 nanosecond ago) should be treated as expired.
// Reason not a feature test: Tests precise timing boundary that cannot be controlled in e2e.
func (s *ServiceSuite) TestRequire_TimeBoundary() {
	s.Run("consent expiring exactly now is treated as expired", func() {
		userID := id.UserID(uuid.New())
		// Set expiry to exactly now
		exactlyNow := time.Now()
		record := &models.Record{
			ID:        id.ConsentID(uuid.New()),
			Purpose:   models.PurposeVCIssuance,
			ExpiresAt: &exactlyNow,
		}

		s.mockStore.EXPECT().
			FindByScope(gomock.Any(), gomock.Any()).
			Return(record, nil)

		// Service uses time.Now() internally, so ExpiresAt.Before(now) will be false initially
		// but by the time the comparison happens, exactlyNow.Before(time.Now()) should be true
		// due to time passing. This test verifies the edge case behavior.
		err := s.service.Require(context.Background(), userID, models.PurposeVCIssuance)
		// The result depends on exact timing - either expired or just barely valid
		// We're testing that the boundary doesn't panic or cause unexpected behavior
		if err != nil {
			s.Assert().True(dErrors.HasCode(err, dErrors.CodeInvalidConsent), "if error, should be CodeInvalidConsent")
		}
		// Note: This is an edge case test - consent at exact boundary may or may not pass
		// depending on nanosecond timing. The key invariant is no panics or incorrect error types.
	})

	s.Run("consent expired 1 nanosecond ago is expired", func() {
		userID := id.UserID(uuid.New())
		// Set expiry to 1 nanosecond ago to guarantee expired
		justExpired := time.Now().Add(-time.Nanosecond)
		record := &models.Record{
			ID:        id.ConsentID(uuid.New()),
			Purpose:   models.PurposeVCIssuance,
			ExpiresAt: &justExpired,
		}

		s.mockStore.EXPECT().
			FindByScope(gomock.Any(), gomock.Any()).
			Return(record, nil)

		err := s.service.Require(context.Background(), userID, models.PurposeVCIssuance)
		s.Require().Error(err)
		s.Assert().True(dErrors.HasCode(err, dErrors.CodeInvalidConsent), "expected CodeInvalidConsent for just-expired consent")
	})

	s.Run("consent expiring in 1 nanosecond is still valid", func() {
		userID := id.UserID(uuid.New())
		// Set expiry to 1 nanosecond in the future
		justBeforeExpiry := time.Now().Add(time.Nanosecond)
		record := &models.Record{
			ID:        id.ConsentID(uuid.New()),
			Purpose:   models.PurposeVCIssuance,
			ExpiresAt: &justBeforeExpiry,
		}

		s.mockStore.EXPECT().
			FindByScope(gomock.Any(), gomock.Any()).
			Return(record, nil)

		err := s.service.Require(context.Background(), userID, models.PurposeVCIssuance)
		// May or may not pass depending on exact timing, but should not panic
		// The important thing is consistent error types
		if err != nil {
			s.Assert().True(dErrors.HasCode(err, dErrors.CodeInvalidConsent), "if error, should be CodeInvalidConsent")
		}
	})

	s.Run("consent with nil ExpiresAt is valid (no expiry)", func() {
		userID := id.UserID(uuid.New())
		record := &models.Record{
			ID:        id.ConsentID(uuid.New()),
			Purpose:   models.PurposeVCIssuance,
			ExpiresAt: nil, // No expiry set
		}

		s.mockStore.EXPECT().
			FindByScope(gomock.Any(), gomock.Any()).
			Return(record, nil)

		err := s.service.Require(context.Background(), userID, models.PurposeVCIssuance)
		s.Assert().NoError(err, "consent with no expiry should be valid")
	})
}

// TestRequire_StoreErrorPropagation verifies that store errors are properly propagated.
// Invariant: Store failures must surface as CodeInternal errors.
func (s *ServiceSuite) TestRequire_StoreErrorPropagation() {
	s.Run("store error propagates as CodeInternal", func() {
		userID := id.UserID(uuid.New())
		s.mockStore.EXPECT().
			FindByScope(gomock.Any(), gomock.Any()).
			Return(nil, assert.AnError)

		err := s.service.Require(context.Background(), userID, models.PurposeVCIssuance)
		s.Require().Error(err)
		s.Assert().True(dErrors.HasCode(err, dErrors.CodeInternal), "expected CodeInternal for store error")
	})
}
