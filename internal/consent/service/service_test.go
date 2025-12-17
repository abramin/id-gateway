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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	"credo/internal/audit"
	"credo/internal/consent/models"
	"credo/internal/consent/service/mocks"
	"credo/internal/consent/store"
	dErrors "credo/pkg/domain-errors"
)

type ServiceSuite struct {
	suite.Suite
	ctrl       *gomock.Controller
	mockStore  *mocks.MockStore
	service    *Service
	auditStore *audit.InMemoryStore
}

func (s *ServiceSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.mockStore = mocks.NewMockStore(s.ctrl)
	s.auditStore = audit.NewInMemoryStore()
	auditor := audit.NewPublisher(s.auditStore)
	s.service = NewService(
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
	s.T().Run("missing userID returns CodeUnauthorized", func(t *testing.T) {
		_, err := s.service.Grant(context.Background(), "", []models.Purpose{models.PurposeLogin})
		require.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeUnauthorized), "expected CodeUnauthorized for missing userID")
	})

	s.T().Run("empty purposes returns CodeBadRequest", func(t *testing.T) {
		_, err := s.service.Grant(context.Background(), "user123", []models.Purpose{})
		require.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeBadRequest), "expected CodeBadRequest for empty purposes")
	})

	s.T().Run("invalid purpose returns CodeBadRequest", func(t *testing.T) {
		_, err := s.service.Grant(context.Background(), "user123", []models.Purpose{"invalid_purpose"})
		require.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeBadRequest), "expected CodeBadRequest for invalid purpose")
	})
}

// TestGrant_StoreErrorPropagation verifies that store errors are properly wrapped and propagated.
// Invariant: Store failures must surface as CodeInternal errors without leaking implementation details.
// Reason not a feature test: Tests internal error wrapping boundary; feature tests cannot induce store failures.
func (s *ServiceSuite) TestGrant_StoreErrorPropagation() {
	s.T().Run("store error on find propagates as CodeInternal", func(t *testing.T) {
		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeLogin).
			Return(nil, assert.AnError)

		_, err := s.service.Grant(context.Background(), "user123", []models.Purpose{models.PurposeLogin})
		require.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeInternal), "expected CodeInternal for store find error")
	})

	s.T().Run("store error on save propagates as CodeInternal", func(t *testing.T) {
		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeLogin).
			Return(nil, store.ErrNotFound)

		s.mockStore.EXPECT().
			Save(gomock.Any(), gomock.Any()).
			Return(assert.AnError)

		_, err := s.service.Grant(context.Background(), "user123", []models.Purpose{models.PurposeLogin})
		require.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeInternal), "expected CodeInternal for store save error")
	})
}

// =============================================================================
// Revoke Tests - Error Propagation & Validation
// =============================================================================

// TestRevoke_ValidationErrors verifies domain error code mapping for invalid input.
// Invariant: Invalid input must return appropriate domain error codes.
// Reason not a feature test: Feature tests verify HTTP status codes; this tests internal error code mapping.
func (s *ServiceSuite) TestRevoke_ValidationErrors() {
	s.T().Run("missing userID returns CodeUnauthorized", func(t *testing.T) {
		_, err := s.service.Revoke(context.Background(), "", []models.Purpose{models.PurposeLogin})
		require.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeUnauthorized), "expected CodeUnauthorized for missing userID")
	})

	s.T().Run("invalid purpose returns CodeBadRequest", func(t *testing.T) {
		_, err := s.service.Revoke(context.Background(), "user123", []models.Purpose{"invalid_purpose"})
		require.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeBadRequest), "expected CodeBadRequest for invalid purpose")
	})
}

// TestRevoke_StoreErrorPropagation verifies that store errors are properly wrapped and propagated.
// Invariant: Store failures must surface as CodeInternal errors.
// Reason not a feature test: Tests internal error wrapping boundary; feature tests cannot induce store failures.
func (s *ServiceSuite) TestRevoke_StoreErrorPropagation() {
	s.T().Run("store error on find propagates as CodeInternal", func(t *testing.T) {
		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeLogin).
			Return(nil, assert.AnError)

		_, err := s.service.Revoke(context.Background(), "user123", []models.Purpose{models.PurposeLogin})
		require.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeInternal), "expected CodeInternal for store find error")
	})

	s.T().Run("store error on revoke propagates as CodeInternal", func(t *testing.T) {
		existing := &models.Record{
			ID:      "consent_1",
			Purpose: models.PurposeLogin,
		}

		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeLogin).
			Return(existing, nil)

		s.mockStore.EXPECT().
			RevokeByUserAndPurpose(gomock.Any(), "user123", models.PurposeLogin, gomock.Any()).
			Return(nil, assert.AnError)

		_, err := s.service.Revoke(context.Background(), "user123", []models.Purpose{models.PurposeLogin})
		require.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeInternal), "expected CodeInternal for store revoke error")
	})
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
	s.T().Run("missing userID returns CodeUnauthorized", func(t *testing.T) {
		err := s.service.Require(context.Background(), "", models.PurposeVCIssuance)
		require.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeUnauthorized), "expected CodeUnauthorized for missing userID")
	})

	s.T().Run("invalid purpose returns CodeBadRequest", func(t *testing.T) {
		err := s.service.Require(context.Background(), "user123", "invalid_purpose")
		require.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeBadRequest), "expected CodeBadRequest for invalid purpose")
	})
}

// TestRequire_ConsentStates verifies correct error codes for different consent states.
// Invariant: Missing consent must return CodeMissingConsent; revoked/expired must return CodeInvalidConsent.
// Reason not a feature test: Tests specific domain error codes that map to HTTP responses in handlers.
func (s *ServiceSuite) TestRequire_ConsentStates() {
	now := time.Now()
	future := now.Add(time.Hour)
	expired := now.Add(-time.Hour)

	s.T().Run("missing consent returns CodeMissingConsent", func(t *testing.T) {
		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeVCIssuance).
			Return(nil, store.ErrNotFound)

		err := s.service.Require(context.Background(), "user123", models.PurposeVCIssuance)
		require.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeMissingConsent), "expected CodeMissingConsent for missing consent")
	})

	s.T().Run("revoked consent returns CodeInvalidConsent", func(t *testing.T) {
		record := &models.Record{
			ID:        "consent_1",
			Purpose:   models.PurposeVCIssuance,
			RevokedAt: &now,
		}

		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeVCIssuance).
			Return(record, nil)

		err := s.service.Require(context.Background(), "user123", models.PurposeVCIssuance)
		require.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeInvalidConsent), "expected CodeInvalidConsent for revoked consent")
	})

	s.T().Run("expired consent returns CodeInvalidConsent", func(t *testing.T) {
		record := &models.Record{
			ID:        "consent_1",
			Purpose:   models.PurposeVCIssuance,
			ExpiresAt: &expired,
		}

		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeVCIssuance).
			Return(record, nil)

		err := s.service.Require(context.Background(), "user123", models.PurposeVCIssuance)
		require.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeInvalidConsent), "expected CodeInvalidConsent for expired consent")
	})

	s.T().Run("active consent returns nil", func(t *testing.T) {
		record := &models.Record{
			ID:        "consent_1",
			Purpose:   models.PurposeVCIssuance,
			ExpiresAt: &future,
		}

		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeVCIssuance).
			Return(record, nil)

		err := s.service.Require(context.Background(), "user123", models.PurposeVCIssuance)
		assert.NoError(t, err)
	})
}

// TestRequire_StoreErrorPropagation verifies that store errors are properly propagated.
// Invariant: Store failures must surface as CodeInternal errors.
func (s *ServiceSuite) TestRequire_StoreErrorPropagation() {
	s.T().Run("store error propagates as CodeInternal", func(t *testing.T) {
		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeVCIssuance).
			Return(nil, assert.AnError)

		err := s.service.Require(context.Background(), "user123", models.PurposeVCIssuance)
		require.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeInternal), "expected CodeInternal for store error")
	})
}
