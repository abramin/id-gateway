package store

// Store tests for consent module following Credo testing doctrine (AGENTS.md, testing.md).
//
// Per testing doctrine, these tests verify store-level invariants:
// - Sentinel error returns (ErrNotFound)
// - Copy semantics (preventing external mutation)
// - CRUD operations for persistence correctness

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"

	"credo/internal/consent/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"
)

type InMemoryStoreSuite struct {
	suite.Suite
	store *InMemoryStore
	ctx   context.Context
}

func (s *InMemoryStoreSuite) SetupTest() {
	s.store = New()
	s.ctx = context.Background()
}

func TestInMemoryStoreSuite(t *testing.T) {
	suite.Run(t, new(InMemoryStoreSuite))
}

// =============================================================================
// Save and Find - Core Persistence
// =============================================================================

// TestSaveAndFind verifies basic persistence operations.
// Invariant: Saved records must be retrievable by user and purpose.
func (s *InMemoryStoreSuite) TestSaveAndFind() {
	s.Run("returns record when found", func() {
		now := time.Now()
		expiry := now.Add(time.Hour)
		record := &models.Record{
			ID:        id.ConsentID(uuid.New()),
			UserID:    id.UserID(uuid.New()),
			Purpose:   models.PurposeLogin,
			GrantedAt: now,
			ExpiresAt: &expiry,
		}

		s.Require().NoError(s.store.Save(s.ctx, record))

		scope, err := models.NewConsentScope(record.UserID, models.PurposeLogin)
		s.Require().NoError(err)
		fetched, err := s.store.FindByScope(s.ctx, scope)
		s.Require().NoError(err)
		s.Assert().Equal(record.ID, fetched.ID)
		s.Assert().Equal(record.UserID, fetched.UserID)
		s.Assert().Equal(record.Purpose, fetched.Purpose)
	})

	s.Run("returns ErrNotFound when record does not exist", func() {
		nonExistentUserID := id.UserID(uuid.New())

		scope, err := models.NewConsentScope(nonExistentUserID, models.PurposeLogin)
		s.Require().NoError(err)
		fetched, err := s.store.FindByScope(s.ctx, scope)
		s.Require().ErrorIs(err, sentinel.ErrNotFound)
		s.Assert().Nil(fetched)
	})

	s.Run("returns ErrConflict when saving duplicate purpose", func() {
		now := time.Now()
		expiry := now.Add(time.Hour)
		userID := id.UserID(uuid.New())
		record := &models.Record{
			ID:        id.ConsentID(uuid.New()),
			UserID:    userID,
			Purpose:   models.PurposeLogin,
			GrantedAt: now,
			ExpiresAt: &expiry,
		}

		s.Require().NoError(s.store.Save(s.ctx, record))
		s.Require().ErrorIs(s.store.Save(s.ctx, record), sentinel.ErrConflict)
	})
}

// =============================================================================
// Update - Timestamp Modifications
// =============================================================================

// TestUpdate verifies record updates are persisted.
// Invariant: Updated fields must be reflected on subsequent reads.
func (s *InMemoryStoreSuite) TestUpdate() {
	s.Run("updates expiry timestamp", func() {
		now := time.Now()
		expiry := now.Add(time.Hour)
		record := &models.Record{
			ID:        id.ConsentID(uuid.New()),
			UserID:    id.UserID(uuid.New()),
			Purpose:   models.PurposeLogin,
			GrantedAt: now,
			ExpiresAt: &expiry,
		}
		s.Require().NoError(s.store.Save(s.ctx, record))

		newExpiry := now.Add(2 * time.Hour)
		record.ExpiresAt = &newExpiry
		s.Require().NoError(s.store.Update(s.ctx, record))

		scope, err := models.NewConsentScope(record.UserID, models.PurposeLogin)
		s.Require().NoError(err)
		fetched, err := s.store.FindByScope(s.ctx, scope)
		s.Require().NoError(err)
		s.Require().NotNil(fetched.ExpiresAt)
		s.Assert().Equal(newExpiry, *fetched.ExpiresAt)
	})
}

// =============================================================================
// Execute - Atomic Mutation
// =============================================================================

// TestExecute verifies Execute applies validated mutations under lock.
// Invariant: Mutations should be persisted atomically.
func (s *InMemoryStoreSuite) TestExecute() {
	s.Run("sets RevokedAt on record", func() {
		now := time.Now()
		expiry := now.Add(time.Hour)
		record := &models.Record{
			ID:        id.ConsentID(uuid.New()),
			UserID:    id.UserID(uuid.New()),
			Purpose:   models.PurposeLogin,
			GrantedAt: now,
			ExpiresAt: &expiry,
		}
		s.Require().NoError(s.store.Save(s.ctx, record))

		revokeTime := now.Add(30 * time.Minute)
		scope, err := models.NewConsentScope(record.UserID, models.PurposeLogin)
		s.Require().NoError(err)
		res, err := s.store.Execute(s.ctx, scope,
			func(_ *models.Record) error { return nil },
			func(existing *models.Record) { existing.RevokedAt = &revokeTime },
		)
		s.Require().NoError(err)
		s.Assert().Equal(record.ID, res.ID)
		s.Require().NotNil(res.RevokedAt)
		s.Assert().Equal(revokeTime, *res.RevokedAt)
	})
}

// =============================================================================
// Copy Semantics - Mutation Prevention
// =============================================================================

// TestCopySemanticsPreventsMutation verifies that returned records are copies.
// Invariant: Modifying a returned record must not affect stored data.
// Reason this is a unit test: Tests internal implementation detail (copy semantics)
// that cannot be observed via feature tests.
func (s *InMemoryStoreSuite) TestCopySemanticsPreventsMutation() {
	s.Run("modifying fetched record does not affect stored data", func() {
		now := time.Now()
		expiry := now.Add(time.Hour)
		originalUserID := id.UserID(uuid.New())
		record := &models.Record{
			ID:        id.ConsentID(uuid.New()),
			UserID:    originalUserID,
			Purpose:   models.PurposeLogin,
			GrantedAt: now,
			ExpiresAt: &expiry,
		}
		s.Require().NoError(s.store.Save(s.ctx, record))

		// Fetch via List and modify the returned copy
		list, err := s.store.ListByUser(s.ctx, originalUserID, nil)
		s.Require().NoError(err)
		s.Require().Len(list, 1)

		// Mutate the fetched record
		list[0].UserID = id.UserID(uuid.New())

		// Verify original is unchanged
		scope, err := models.NewConsentScope(originalUserID, models.PurposeLogin)
		s.Require().NoError(err)
		fetched, err := s.store.FindByScope(s.ctx, scope)
		s.Require().NoError(err)
		s.Assert().Equal(originalUserID, fetched.UserID, "stored record should remain unchanged")
	})
}

// =============================================================================
// Delete - GDPR Erasure
// =============================================================================

// TestDeleteRemovesAllUserRecords verifies complete user data removal.
// Invariant: After deletion, no records should exist for the user.
func (s *InMemoryStoreSuite) TestDeleteRemovesAllUserRecords() {
	s.Run("removes all records for user", func() {
		now := time.Now()
		expiry := now.Add(time.Hour)
		userID := id.UserID(uuid.New())

		// Save multiple records
		for _, purpose := range []models.Purpose{models.PurposeLogin, models.PurposeRegistryCheck} {
			record := &models.Record{
				ID:        id.ConsentID(uuid.New()),
				UserID:    userID,
				Purpose:   purpose,
				GrantedAt: now,
				ExpiresAt: &expiry,
			}
			s.Require().NoError(s.store.Save(s.ctx, record))
		}

		// Delete all
		s.Require().NoError(s.store.DeleteByUser(s.ctx, userID))

		// Verify all are gone
		scope, err := models.NewConsentScope(userID, models.PurposeLogin)
		s.Require().NoError(err)
		fetched, err := s.store.FindByScope(s.ctx, scope)
		s.Require().ErrorIs(err, sentinel.ErrNotFound)
		s.Assert().Nil(fetched)

		scope, err = models.NewConsentScope(userID, models.PurposeRegistryCheck)
		s.Require().NoError(err)
		fetched, err = s.store.FindByScope(s.ctx, scope)
		s.Require().ErrorIs(err, sentinel.ErrNotFound)
		s.Assert().Nil(fetched)
	})
}
