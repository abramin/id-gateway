//go:build integration

package store_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"credo/internal/consent/models"
	"credo/internal/consent/store"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/sentinel"
	"credo/pkg/testutil"
	"credo/pkg/testutil/containers"
)

type PostgresStoreSuite struct {
	suite.Suite
	postgres *containers.PostgresContainer
	store    *store.PostgresStore
	tenantID id.TenantID
}

func TestPostgresStoreSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	suite.Run(t, new(PostgresStoreSuite))
}

func (s *PostgresStoreSuite) SetupSuite() {
	mgr := containers.GetManager()
	s.postgres = mgr.GetPostgres(s.T())
	s.store = store.NewPostgres(s.postgres.DB)
}

func (s *PostgresStoreSuite) SetupTest() {
	ctx := context.Background()

	// Truncate in dependency order
	err := s.postgres.TruncateTables(ctx, "consents", "users", "clients", "tenants")
	s.Require().NoError(err)

	// Create a tenant using shared helper
	s.tenantID = s.postgres.CreateTestTenant(ctx, s.T())
}

func (s *PostgresStoreSuite) createTestUser(ctx context.Context) id.UserID {
	return s.postgres.CreateTestUser(ctx, s.T(), s.tenantID)
}

// TestConcurrentGrantRevoke verifies that concurrent grant/revoke operations
// on the same consent record result in a consistent final state.
func (s *PostgresStoreSuite) TestConcurrentGrantRevoke() {
	ctx := context.Background()
	userID := s.createTestUser(ctx)

	// Create initial consent
	consent := testutil.NewTestConsent(userID, models.PurposeLogin)
	err := s.store.Save(ctx, consent)
	s.Require().NoError(err)

	const goroutines = 50
	var wg sync.WaitGroup
	var revokeCount, grantCount atomic.Int32

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			scope := models.ConsentScope{UserID: userID, Purpose: models.PurposeLogin}

			if idx%2 == 0 {
				// Revoke
				_, err := s.store.Execute(ctx, scope,
					func(r *models.Record) error {
						if r.RevokedAt != nil {
							return dErrors.New(dErrors.CodeConflict, "already revoked")
						}
						return nil
					},
					func(r *models.Record) bool {
						now := time.Now()
						r.RevokedAt = &now
						return true
					},
				)
				if err == nil {
					revokeCount.Add(1)
				}
			} else {
				// Re-grant (clear revoked_at)
				_, err := s.store.Execute(ctx, scope,
					func(r *models.Record) error {
						if r.RevokedAt == nil {
							return dErrors.New(dErrors.CodeConflict, "not revoked")
						}
						return nil
					},
					func(r *models.Record) bool {
						r.RevokedAt = nil
						r.GrantedAt = time.Now()
						return true
					},
				)
				if err == nil {
					grantCount.Add(1)
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify final state is consistent (either revoked or not, not corrupted)
	found, err := s.store.FindByScope(ctx, models.ConsentScope{UserID: userID, Purpose: models.PurposeLogin})
	s.Require().NoError(err)
	s.NotNil(found)
	// At least some operations should have succeeded
	s.Greater(revokeCount.Load()+grantCount.Load(), int32(0))
}

// TestExecuteCallbackAtomicity verifies that validation errors trigger rollback
// and don't corrupt state.
func (s *PostgresStoreSuite) TestExecuteCallbackAtomicity() {
	ctx := context.Background()
	userID := s.createTestUser(ctx)

	// Create consent
	consent := testutil.NewTestConsent(userID, models.PurposeRegistryCheck)
	err := s.store.Save(ctx, consent)
	s.Require().NoError(err)

	scope := models.ConsentScope{UserID: userID, Purpose: models.PurposeRegistryCheck}
	validationErr := dErrors.New(dErrors.CodeForbidden, "validation failed intentionally")

	// Execute with failing validation
	_, err = s.store.Execute(ctx, scope,
		func(r *models.Record) error {
			return validationErr
		},
		func(r *models.Record) bool {
			// This should NOT be called since validation fails
			now := time.Now()
			r.RevokedAt = &now
			return true
		},
	)

	s.Error(err)
	s.ErrorIs(err, validationErr)

	// Verify record is unchanged
	found, err := s.store.FindByScope(ctx, scope)
	s.Require().NoError(err)
	s.Nil(found.RevokedAt, "consent should not be revoked after validation failure")
}

// TestTransactionRollbackOnValidationFailure verifies domain errors don't corrupt state.
func (s *PostgresStoreSuite) TestTransactionRollbackOnValidationFailure() {
	ctx := context.Background()
	userID := s.createTestUser(ctx)

	// Create consent
	consent := testutil.NewTestConsent(userID, models.PurposeVCIssuance)
	originalGrantedAt := consent.GrantedAt
	err := s.store.Save(ctx, consent)
	s.Require().NoError(err)

	scope := models.ConsentScope{UserID: userID, Purpose: models.PurposeVCIssuance}

	// Run multiple concurrent Execute calls that fail validation
	testutil.RunConcurrent(30, func(_ int) error {
		_, err := s.store.Execute(ctx, scope,
			func(r *models.Record) error {
				return dErrors.New(dErrors.CodeForbidden, "always fail")
			},
			func(r *models.Record) bool {
				r.GrantedAt = time.Now().Add(100 * time.Hour)
				return true
			},
		)
		return err
	})

	// Verify original state is preserved
	found, err := s.store.FindByScope(ctx, scope)
	s.Require().NoError(err)
	s.WithinDuration(originalGrantedAt, found.GrantedAt, time.Second,
		"granted_at should be unchanged after failed validations")
}

// TestDeadlockDetection verifies that concurrent Execute operations on different
// users don't deadlock (they should acquire locks in parallel without blocking).
func (s *PostgresStoreSuite) TestDeadlockDetection() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create multiple users with consents
	const users = 5
	userIDs := make([]id.UserID, users)
	for i := 0; i < users; i++ {
		userIDs[i] = s.createTestUser(ctx)
		consent := testutil.NewTestConsent(userIDs[i], models.PurposeLogin)
		err := s.store.Save(ctx, consent)
		s.Require().NoError(err)
	}

	result := testutil.RunConcurrentCtx(ctx, 50, func(ctx context.Context, idx int) error {
		userID := userIDs[idx%users]
		scope := models.ConsentScope{UserID: userID, Purpose: models.PurposeLogin}
		_, err := s.store.Execute(ctx, scope,
			func(r *models.Record) error { return nil },
			func(r *models.Record) bool { r.GrantedAt = time.Now(); return true },
		)
		return err
	})

	s.Equal(int32(0), result.Errors, "no errors expected when operating on different users")
}

// TestConcurrentSaveConflict verifies Save conflict handling under concurrency.
func (s *PostgresStoreSuite) TestConcurrentSaveConflict() {
	ctx := context.Background()
	userID := s.createTestUser(ctx)

	result := testutil.RunConcurrent(50, func(_ int) error {
		consent := testutil.NewTestConsent(userID, models.PurposeLogin)
		return s.store.Save(ctx, consent)
	})

	// Exactly one should succeed due to unique constraint
	s.Equal(int32(1), result.Successes, "exactly one save should succeed")
	s.Equal(int32(49), result.Conflicts, "all others should conflict")
}

// TestRevokeAllByUserConcurrency verifies RevokeAllByUser under concurrent access.
func (s *PostgresStoreSuite) TestRevokeAllByUserConcurrency() {
	ctx := context.Background()
	userID := s.createTestUser(ctx)

	// Create multiple consents for the user
	purposes := []models.Purpose{
		models.PurposeLogin,
		models.PurposeRegistryCheck,
		models.PurposeVCIssuance,
		models.PurposeDecision,
	}

	for _, purpose := range purposes {
		consent := testutil.NewTestConsent(userID, purpose)
		err := s.store.Save(ctx, consent)
		s.Require().NoError(err)
	}

	var totalRevoked atomic.Int32
	result := testutil.RunConcurrent(10, func(_ int) error {
		count, err := s.store.RevokeAllByUser(ctx, userID, time.Now())
		if err == nil {
			totalRevoked.Add(int32(count))
		}
		return err
	})

	s.Equal(int32(0), result.Errors, "no errors expected")
	// Total revoked should equal the number of consents (each revoked exactly once)
	s.Equal(int32(len(purposes)), totalRevoked.Load(),
		"total revoked should equal number of consents")

	// Verify all are revoked
	records, err := s.store.ListByUser(ctx, userID, nil)
	s.Require().NoError(err)
	for _, r := range records {
		s.NotNil(r.RevokedAt, "all consents should be revoked")
	}
}

// TestListByUserUnderConcurrentModification verifies list consistency during concurrent updates.
func (s *PostgresStoreSuite) TestListByUserUnderConcurrentModification() {
	ctx := context.Background()
	userID := s.createTestUser(ctx)

	// Create initial consents
	for _, purpose := range []models.Purpose{models.PurposeLogin, models.PurposeRegistryCheck} {
		consent := testutil.NewTestConsent(userID, purpose)
		err := s.store.Save(ctx, consent)
		s.Require().NoError(err)
	}

	const goroutines = 30
	var wg sync.WaitGroup
	var listErrors atomic.Int32

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			if idx%3 == 0 {
				// List
				records, err := s.store.ListByUser(ctx, userID, nil)
				if err != nil {
					listErrors.Add(1)
				} else {
					// List should always return consistent results (non-nil slice)
					s.NotNil(records)
				}
			} else {
				// Update via Execute
				scope := models.ConsentScope{UserID: userID, Purpose: models.PurposeLogin}
				_, _ = s.store.Execute(ctx, scope,
					func(r *models.Record) error { return nil },
					func(r *models.Record) bool {
						r.GrantedAt = time.Now()
						return true
					},
				)
			}
		}(i)
	}

	wg.Wait()

	s.Equal(int32(0), listErrors.Load(), "no list errors expected")
}

// TestNotFoundError verifies proper error handling for non-existent records.
func (s *PostgresStoreSuite) TestNotFoundError() {
	ctx := context.Background()
	userID := s.createTestUser(ctx)

	// FindByScope with no consent
	scope := models.ConsentScope{UserID: userID, Purpose: models.PurposeLogin}
	_, err := s.store.FindByScope(ctx, scope)
	s.ErrorIs(err, sentinel.ErrNotFound)

	// Execute on non-existent consent
	_, err = s.store.Execute(ctx, scope,
		func(r *models.Record) error { return nil },
		func(r *models.Record) bool { return true },
	)
	s.ErrorIs(err, sentinel.ErrNotFound)
}
