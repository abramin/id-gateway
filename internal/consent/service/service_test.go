package service

//go:generate mockgen -source=service.go -destination=mocks/mocks.go -package=mocks Store

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	"credo/internal/audit"
	"credo/internal/consent/models"
	"credo/internal/consent/service/mocks"
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
		slog.Default(),
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

func (s *ServiceSuite) TestGrant() {
	s.T().Run("creates new consent when not exists", func(t *testing.T) {
		purposes := []models.Purpose{models.PurposeLogin}

		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeLogin).
			Return(nil, nil)

		s.mockStore.EXPECT().
			Save(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, consent *models.Record) error {
				assert.Equal(t, "user123", consent.UserID)
				assert.Equal(t, models.PurposeLogin, consent.Purpose)
				assert.True(t, strings.HasPrefix(consent.ID, "consent_"))
				assert.False(t, consent.GrantedAt.IsZero())
				require.NotNil(t, consent.ExpiresAt)
				assert.True(t, consent.ExpiresAt.After(consent.GrantedAt))
				assert.Nil(t, consent.RevokedAt)
				return nil
			})

		granted, err := s.service.Grant(context.Background(), "user123", purposes)
		assert.NoError(t, err)
		assert.Len(t, granted.Granted, 1)
		assert.Equal(t, models.PurposeLogin, granted.Granted[0].Purpose)
	})

	s.T().Run("renews existing active consent", func(t *testing.T) {
		now := time.Now()
		expiry := now.Add(24 * time.Hour)
		existing := &models.Record{
			ID:        "consent_abc",
			UserID:    "user123",
			Purpose:   models.PurposeLogin,
			GrantedAt: now.Add(-24 * time.Hour),
			ExpiresAt: &expiry,
		}

		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeLogin).
			Return(existing, nil)

		s.mockStore.EXPECT().
			Update(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, consent *models.Record) error {
				assert.Equal(t, "consent_abc", consent.ID)
				assert.False(t, consent.GrantedAt.IsZero())
				require.NotNil(t, consent.ExpiresAt)
				assert.True(t, consent.ExpiresAt.After(consent.GrantedAt))
				assert.Nil(t, consent.RevokedAt)
				return nil
			})

		res, err := s.service.Grant(context.Background(), "user123", []models.Purpose{models.PurposeLogin})
		assert.NoError(t, err)
		assert.Len(t, res.Granted, 1)
		assert.Equal(t, models.StatusActive, res.Granted[0].Status)
	})

	s.T().Run("idempotent within 5-minute window - returns existing without update", func(t *testing.T) {
		now := time.Now()
		expiry := now.Add(24 * time.Hour)
		// Consent granted 2 minutes ago (within 5-minute window)
		existing := &models.Record{
			ID:        "consent_recent",
			UserID:    "user123",
			Purpose:   models.PurposeLogin,
			GrantedAt: now.Add(-2 * time.Minute),
			ExpiresAt: &expiry,
		}

		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeLogin).
			Return(existing, nil)

		// Should NOT call Update or Save - no store write expected
		// No need to set expectations for Update/Save

		res, err := s.service.Grant(context.Background(), "user123", []models.Purpose{models.PurposeLogin})
		assert.NoError(t, err)
		assert.Len(t, res.Granted, 1)
		assert.Equal(t, existing.Purpose, res.Granted[0].Purpose)
		// Verify timestamps weren't updated
		assert.Equal(t, existing.GrantedAt, res.Granted[0].GrantedAt)
		assert.Equal(t, existing.ExpiresAt, res.Granted[0].ExpiresAt)
	})

	s.T().Run("updates consent after 5-minute window expires", func(t *testing.T) {
		now := time.Now()
		expiry := now.Add(24 * time.Hour)
		// Consent granted 6 minutes ago (outside 5-minute window)
		oldGrantedAt := now.Add(-6 * time.Minute)
		existing := &models.Record{
			ID:        "consent_old",
			UserID:    "user123",
			Purpose:   models.PurposeLogin,
			GrantedAt: oldGrantedAt,
			ExpiresAt: &expiry,
		}

		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeLogin).
			Return(existing, nil)

		s.mockStore.EXPECT().
			Update(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, consent *models.Record) error {
				assert.Equal(t, "consent_old", consent.ID)
				// Should have new timestamps (service mutates the existing object)
				assert.True(t, consent.GrantedAt.After(oldGrantedAt), "GrantedAt should be updated")
				assert.True(t, consent.ExpiresAt.After(expiry), "ExpiresAt should be extended")
				return nil
			})

		res, err := s.service.Grant(context.Background(), "user123", []models.Purpose{models.PurposeLogin})
		assert.NoError(t, err)
		assert.Len(t, res.Granted, 1)
		assert.Greater(t, res.Granted[0].GrantedAt, existing.GrantedAt)
	})

	s.T().Run("always updates expired consent regardless of time window", func(t *testing.T) {
		now := time.Now()
		// Consent granted 2 minutes ago but already expired
		expiry := now.Add(-1 * time.Minute)
		oldGrantedAt := now.Add(-2 * time.Minute)
		existing := &models.Record{
			ID:        "consent_expired",
			UserID:    "user123",
			Purpose:   models.PurposeLogin,
			GrantedAt: oldGrantedAt,
			ExpiresAt: &expiry,
		}

		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeLogin).
			Return(existing, nil)

		s.mockStore.EXPECT().
			Update(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, consent *models.Record) error {
				assert.Equal(t, "consent_expired", consent.ID)
				// Should have new timestamps even though within 5-min window
				assert.True(t, consent.GrantedAt.After(oldGrantedAt), "GrantedAt should be updated")
				assert.True(t, consent.ExpiresAt.After(expiry), "ExpiresAt should be extended")
				assert.Nil(t, consent.RevokedAt)
				return nil
			})

		res, err := s.service.Grant(context.Background(), "user123", []models.Purpose{models.PurposeLogin})
		assert.NoError(t, err)
		assert.Len(t, res.Granted, 1)
		assert.Greater(t, res.Granted[0].GrantedAt, existing.GrantedAt)
	})

	s.T().Run("always updates revoked consent regardless of time window", func(t *testing.T) {
		now := time.Now()
		expiry := now.Add(24 * time.Hour)
		revokedAt := now.Add(-1 * time.Minute)
		oldGrantedAt := now.Add(-2 * time.Minute)
		// Consent granted 2 minutes ago but revoked
		existing := &models.Record{
			ID:        "consent_revoked",
			UserID:    "user123",
			Purpose:   models.PurposeLogin,
			GrantedAt: oldGrantedAt,
			ExpiresAt: &expiry,
			RevokedAt: &revokedAt,
		}

		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeLogin).
			Return(existing, nil)

		s.mockStore.EXPECT().
			Update(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, consent *models.Record) error {
				assert.Equal(t, "consent_revoked", consent.ID)
				// Should have new timestamps even though within 5-min window
				assert.True(t, consent.GrantedAt.After(oldGrantedAt), "GrantedAt should be updated")
				assert.True(t, consent.ExpiresAt.After(expiry), "ExpiresAt should be extended")
				// RevokedAt should be cleared
				assert.Nil(t, consent.RevokedAt)
				return nil
			})

		res, err := s.service.Grant(context.Background(), "user123", []models.Purpose{models.PurposeLogin})
		assert.NoError(t, err)
		assert.Len(t, res.Granted, 1)
		assert.Greater(t, res.Granted[0].GrantedAt, existing.GrantedAt)
	})

	s.T().Run("grants multiple purposes", func(t *testing.T) {
		purposes := []models.Purpose{models.PurposeLogin, models.PurposeRegistryCheck}

		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeLogin).
			Return(nil, nil)

		s.mockStore.EXPECT().
			Save(gomock.Any(), gomock.Any()).
			Return(nil)

		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeRegistryCheck).
			Return(nil, nil)

		s.mockStore.EXPECT().
			Save(gomock.Any(), gomock.Any()).
			Return(nil)

		granted, err := s.service.Grant(context.Background(), "user123", purposes)
		assert.NoError(t, err)
		assert.Len(t, granted.Granted, 2)
	})

	s.T().Run("emits audit with reason for grant", func(t *testing.T) {
		s.auditStore.Clear()
		purposes := []models.Purpose{models.PurposeLogin}

		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeLogin).
			Return(nil, nil)

		s.mockStore.EXPECT().
			Save(gomock.Any(), gomock.Any()).
			Return(nil)

		_, err := s.service.Grant(context.Background(), "user123", purposes)
		assert.NoError(t, err)

		events, auditErr := s.auditStore.ListByUser(context.Background(), "user123")
		require.NoError(t, auditErr)
		require.Len(t, events, 1)
		assert.Equal(t, "consent_granted", events[0].Action)
		assert.Equal(t, "granted", events[0].Decision)
		assert.Equal(t, "user_initiated", events[0].Reason)
	})

	s.T().Run("validation errors", func(t *testing.T) {
		// Missing userID
		_, err := s.service.Grant(context.Background(), "", []models.Purpose{models.PurposeLogin})
		assert.True(t, dErrors.Is(err, dErrors.CodeUnauthorized))

		// Empty purposes
		_, err = s.service.Grant(context.Background(), "user123", []models.Purpose{})
		assert.True(t, dErrors.Is(err, dErrors.CodeBadRequest))

		// Invalid purpose
		_, err = s.service.Grant(context.Background(), "user123", []models.Purpose{"invalid"})
		assert.True(t, dErrors.Is(err, dErrors.CodeBadRequest))
	})

	s.T().Run("store error on find", func(t *testing.T) {
		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeLogin).
			Return(nil, assert.AnError)

		granted, err := s.service.Grant(context.Background(), "user123", []models.Purpose{models.PurposeLogin})
		assert.Error(t, err)
		assert.Nil(t, granted)
	})

	s.T().Run("store error on save", func(t *testing.T) {
		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeLogin).
			Return(nil, nil)

		s.mockStore.EXPECT().
			Save(gomock.Any(), gomock.Any()).
			Return(assert.AnError)

		granted, err := s.service.Grant(context.Background(), "user123", []models.Purpose{models.PurposeLogin})
		assert.Error(t, err)
		assert.Nil(t, granted)
	})
}

func (s *ServiceSuite) TestRevoke() {
	s.T().Run("revokes single purpose", func(t *testing.T) {
		now := time.Now()
		existing := &models.Record{
			ID:        "consent_1",
			UserID:    "user123",
			Purpose:   models.PurposeRegistryCheck,
			GrantedAt: now.Add(-24 * time.Hour),
		}

		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeRegistryCheck).
			Return(existing, nil)

		s.mockStore.EXPECT().
			RevokeByUserAndPurpose(gomock.Any(), "user123", models.PurposeRegistryCheck, gomock.Any()).
			Return(existing, nil)

		revoked, err := s.service.Revoke(context.Background(), "user123", []models.Purpose{models.PurposeRegistryCheck})
		assert.NoError(t, err)
		assert.Len(t, revoked.Revoked, 1)
	})

	s.T().Run("revokes multiple purposes", func(t *testing.T) {
		purposes := []models.Purpose{models.PurposeLogin, models.PurposeRegistryCheck}

		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeLogin).
			Return(&models.Record{ID: "consent_1", Purpose: models.PurposeLogin}, nil)

		s.mockStore.EXPECT().
			RevokeByUserAndPurpose(gomock.Any(), "user123", models.PurposeLogin, gomock.Any()).
			Return(&models.Record{}, nil)

		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeRegistryCheck).
			Return(&models.Record{ID: "consent_2", Purpose: models.PurposeRegistryCheck}, nil)

		s.mockStore.EXPECT().
			RevokeByUserAndPurpose(gomock.Any(), "user123", models.PurposeRegistryCheck, gomock.Any()).
			Return(&models.Record{}, nil)

		revoked, err := s.service.Revoke(context.Background(), "user123", purposes)
		assert.NoError(t, err)
		assert.Len(t, revoked.Revoked, 2)
	})

	s.T().Run("skips already revoked consent", func(t *testing.T) {
		now := time.Now()
		revokedAt := now.Add(-time.Hour)
		existing := &models.Record{
			ID:        "consent_1",
			Purpose:   models.PurposeLogin,
			RevokedAt: &revokedAt,
		}

		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeLogin).
			Return(existing, nil)

		revoked, err := s.service.Revoke(context.Background(), "user123", []models.Purpose{models.PurposeLogin})
		assert.NoError(t, err)
		assert.Len(t, revoked.Revoked, 0)
	})

	s.T().Run("skips expired consent", func(t *testing.T) {
		now := time.Now()
		expired := now.Add(-time.Hour)
		existing := &models.Record{
			ID:        "consent_1",
			Purpose:   models.PurposeLogin,
			ExpiresAt: &expired,
		}

		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeLogin).
			Return(existing, nil)

		revoked, err := s.service.Revoke(context.Background(), "user123", []models.Purpose{models.PurposeLogin})
		assert.NoError(t, err)
		assert.Len(t, revoked.Revoked, 0)
	})

	s.T().Run("skips non-existent consent", func(t *testing.T) {
		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeLogin).
			Return(nil, nil)

		revoked, err := s.service.Revoke(context.Background(), "user123", []models.Purpose{models.PurposeLogin})
		assert.NoError(t, err)
		assert.Len(t, revoked.Revoked, 0)
	})

	s.T().Run("validation errors", func(t *testing.T) {
		// Missing userID
		_, err := s.service.Revoke(context.Background(), "", []models.Purpose{models.PurposeLogin})
		assert.True(t, dErrors.Is(err, dErrors.CodeUnauthorized))

		// Invalid purpose
		_, err = s.service.Revoke(context.Background(), "user123", []models.Purpose{"invalid"})
		assert.True(t, dErrors.Is(err, dErrors.CodeBadRequest))
	})

	s.T().Run("with auditor publishes audit event", func(t *testing.T) {
		existing := &models.Record{
			ID:      "consent_1",
			Purpose: models.PurposeRegistryCheck,
		}

		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeRegistryCheck).
			Return(existing, nil)

		s.mockStore.EXPECT().
			RevokeByUserAndPurpose(gomock.Any(), "user123", models.PurposeRegistryCheck, gomock.Any()).
			Return(existing, nil)

		_, err := s.service.Revoke(context.Background(), "user123", []models.Purpose{models.PurposeRegistryCheck})
		assert.NoError(t, err)
	})

	s.T().Run("returns revoked record with revokedAt set", func(t *testing.T) {
		now := time.Now()
		existing := &models.Record{
			ID:        "consent_1",
			UserID:    "user123",
			Purpose:   models.PurposeLogin,
			GrantedAt: now.Add(-24 * time.Hour),
		}
		revokedAt := now.Add(time.Hour)
		updated := *existing
		updated.RevokedAt = &revokedAt

		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeLogin).
			Return(existing, nil)

		s.mockStore.EXPECT().
			RevokeByUserAndPurpose(gomock.Any(), "user123", models.PurposeLogin, gomock.Any()).
			Return(&updated, nil)

		res, err := s.service.Revoke(context.Background(), "user123", []models.Purpose{models.PurposeLogin})
		assert.NoError(t, err)
		assert.Len(t, res.Revoked, 1)
		assert.Equal(t, revokedAt, res.Revoked[0].RevokedAt)
	})
}

func (s *ServiceSuite) TestRequire() {
	now := time.Now()
	future := now.Add(time.Hour)
	expired := now.Add(-time.Hour)

	s.T().Run("allows active consent", func(t *testing.T) {
		s.auditStore.Clear()
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

	s.T().Run("rejects missing consent", func(t *testing.T) {
		s.auditStore.Clear()
		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeVCIssuance).
			Return(nil, nil)

		err := s.service.Require(context.Background(), "user123", models.PurposeVCIssuance)
		assert.True(t, dErrors.Is(err, dErrors.CodeMissingConsent))

		events, auditErr := s.auditStore.ListByUser(context.Background(), "user123")
		require.NoError(t, auditErr)
		require.Len(t, events, 1)
		assert.Equal(t, "consent_check_failed", events[0].Action)
		assert.Equal(t, "denied", events[0].Decision)
		assert.Equal(t, "user_initiated", events[0].Reason)
	})

	s.T().Run("rejects revoked consent", func(t *testing.T) {
		record := &models.Record{
			ID:        "consent_1",
			Purpose:   models.PurposeVCIssuance,
			RevokedAt: &now,
		}

		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeVCIssuance).
			Return(record, nil)

		err := s.service.Require(context.Background(), "user123", models.PurposeVCIssuance)
		assert.True(t, dErrors.Is(err, dErrors.CodeInvalidConsent))
	})

	s.T().Run("rejects expired consent", func(t *testing.T) {
		record := &models.Record{
			ID:        "consent_1",
			Purpose:   models.PurposeVCIssuance,
			ExpiresAt: &expired,
		}

		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeVCIssuance).
			Return(record, nil)

		err := s.service.Require(context.Background(), "user123", models.PurposeVCIssuance)
		assert.True(t, dErrors.Is(err, dErrors.CodeInvalidConsent))
	})

	s.T().Run("validation errors", func(t *testing.T) {
		// Missing userID
		err := s.service.Require(context.Background(), "", models.PurposeVCIssuance)
		assert.True(t, dErrors.Is(err, dErrors.CodeUnauthorized))

		// Invalid purpose
		err = s.service.Require(context.Background(), "user123", "invalid")
		assert.True(t, dErrors.Is(err, dErrors.CodeBadRequest))
	})

	s.T().Run("store error", func(t *testing.T) {
		s.mockStore.EXPECT().
			FindByUserAndPurpose(gomock.Any(), "user123", models.PurposeVCIssuance).
			Return(nil, assert.AnError)

		err := s.service.Require(context.Background(), "user123", models.PurposeVCIssuance)
		assert.Error(t, err)
	})
}
