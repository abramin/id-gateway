//go:build integration

package session_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"

	"credo/internal/auth/models"
	"credo/internal/auth/store/session"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/sentinel"
	"credo/pkg/testutil/containers"
)

type PostgresStoreSuite struct {
	suite.Suite
	postgres *containers.PostgresContainer
	store    *session.PostgresStore
	tenantID id.TenantID
	clientID id.ClientID
	userID   id.UserID
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
	s.store = session.NewPostgres(s.postgres.DB)
}

func (s *PostgresStoreSuite) SetupTest() {
	ctx := context.Background()

	err := s.postgres.TruncateTables(ctx, "sessions", "users", "clients", "tenants")
	s.Require().NoError(err)

	// Create tenant
	s.tenantID = id.TenantID(uuid.New())
	_, err = s.postgres.Exec(ctx, `
		INSERT INTO tenants (id, name, status, created_at, updated_at)
		VALUES ($1, $2, 'active', NOW(), NOW())
	`, uuid.UUID(s.tenantID), "Test Tenant "+uuid.NewString())
	s.Require().NoError(err)

	// Create client
	s.clientID = id.ClientID(uuid.New())
	_, err = s.postgres.Exec(ctx, `
		INSERT INTO clients (id, tenant_id, name, oauth_client_id, redirect_uris, allowed_grants, allowed_scopes, status, created_at, updated_at)
		VALUES ($1, $2, 'Test Client', $3, '["https://example.com/callback"]', '["authorization_code"]', '["openid"]', 'active', NOW(), NOW())
	`, uuid.UUID(s.clientID), uuid.UUID(s.tenantID), "client-"+uuid.NewString())
	s.Require().NoError(err)

	// Create user
	s.userID = id.UserID(uuid.New())
	_, err = s.postgres.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, first_name, last_name, verified, status)
		VALUES ($1, $2, $3, 'Test', 'User', true, 'active')
	`, uuid.UUID(s.userID), uuid.UUID(s.tenantID), "test-"+uuid.NewString()+"@example.com")
	s.Require().NoError(err)
}

func (s *PostgresStoreSuite) newTestSession() *models.Session {
	now := time.Now()
	return &models.Session{
		ID:             id.SessionID(uuid.New()),
		UserID:         s.userID,
		ClientID:       s.clientID,
		TenantID:       s.tenantID,
		RequestedScope: []string{"openid"},
		Status:         models.SessionStatusActive,
		DeviceID:       uuid.NewString(),
		CreatedAt:      now,
		ExpiresAt:      now.Add(24 * time.Hour),
		LastSeenAt:     now,
	}
}

// TestConcurrentSessionRefresh verifies that concurrent Execute calls on the same session
// result in exactly one successful refresh per call.
func (s *PostgresStoreSuite) TestConcurrentSessionRefresh() {
	ctx := context.Background()

	sess := s.newTestSession()
	err := s.store.Create(ctx, sess)
	s.Require().NoError(err)

	const goroutines = 50
	var wg sync.WaitGroup
	var successCount atomic.Int32
	var errors atomic.Int32

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			_, err := s.store.Execute(ctx, sess.ID,
				func(sess *models.Session) error {
					if sess.Status != models.SessionStatusActive {
						return dErrors.New(dErrors.CodeForbidden, "session not active")
					}
					return nil
				},
				func(sess *models.Session) {
					now := time.Now()
					sess.LastRefreshedAt = &now
					sess.LastSeenAt = now
				},
			)
			if err == nil {
				successCount.Add(1)
			} else {
				errors.Add(1)
			}
		}(i)
	}

	wg.Wait()

	// All should succeed since they're all refreshing an active session
	s.Equal(int32(goroutines), successCount.Load(), "all refreshes should succeed")
	s.Equal(int32(0), errors.Load(), "no errors expected")
}

// TestConcurrentRevoke verifies concurrent revocation results in consistent final state.
func (s *PostgresStoreSuite) TestConcurrentRevoke() {
	ctx := context.Background()

	sess := s.newTestSession()
	err := s.store.Create(ctx, sess)
	s.Require().NoError(err)

	const goroutines = 50
	var wg sync.WaitGroup
	var revokeSuccess atomic.Int32
	var alreadyRevoked atomic.Int32

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			err := s.store.RevokeSessionIfActive(ctx, sess.ID, time.Now())
			if err == nil {
				revokeSuccess.Add(1)
			} else if err == session.ErrSessionRevoked {
				alreadyRevoked.Add(1)
			}
		}()
	}

	wg.Wait()

	// Exactly one should succeed, others see already revoked
	s.Equal(int32(1), revokeSuccess.Load(), "exactly one revoke should succeed")
	s.Equal(int32(goroutines-1), alreadyRevoked.Load(), "others should see already revoked")

	// Verify final state
	found, err := s.store.FindByID(ctx, sess.ID)
	s.Require().NoError(err)
	s.Equal(models.SessionStatusRevoked, found.Status)
	s.NotNil(found.RevokedAt)
}

// TestExecuteAtomicity verifies validation errors prevent mutation.
func (s *PostgresStoreSuite) TestExecuteAtomicity() {
	ctx := context.Background()

	sess := s.newTestSession()
	err := s.store.Create(ctx, sess)
	s.Require().NoError(err)

	validationErr := dErrors.New(dErrors.CodeForbidden, "intentional failure")

	// Execute with failing validation
	_, err = s.store.Execute(ctx, sess.ID,
		func(sess *models.Session) error {
			return validationErr
		},
		func(sess *models.Session) {
			// This should NOT be applied
			sess.Status = models.SessionStatusRevoked
		},
	)

	s.ErrorIs(err, validationErr)

	// Verify session unchanged
	found, err := s.store.FindByID(ctx, sess.ID)
	s.Require().NoError(err)
	s.Equal(models.SessionStatusActive, found.Status, "status should be unchanged")
}

// TestListByUserUnderConcurrentModification verifies list consistency during concurrent updates.
func (s *PostgresStoreSuite) TestListByUserUnderConcurrentModification() {
	ctx := context.Background()

	// Create multiple sessions
	sessions := make([]*models.Session, 5)
	for i := 0; i < 5; i++ {
		sessions[i] = s.newTestSession()
		err := s.store.Create(ctx, sessions[i])
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
				list, err := s.store.ListByUser(ctx, s.userID)
				if err != nil {
					listErrors.Add(1)
				} else {
					s.NotNil(list)
				}
			} else {
				// Update via Execute
				sess := sessions[idx%5]
				_, _ = s.store.Execute(ctx, sess.ID,
					func(s *models.Session) error { return nil },
					func(s *models.Session) { s.LastSeenAt = time.Now() },
				)
			}
		}(i)
	}

	wg.Wait()

	s.Equal(int32(0), listErrors.Load(), "no list errors expected")
}

// TestConcurrentCreateDifferentSessions verifies concurrent creation of different sessions.
func (s *PostgresStoreSuite) TestConcurrentCreateDifferentSessions() {
	ctx := context.Background()
	const goroutines = 50

	var wg sync.WaitGroup
	var errors atomic.Int32

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			sess := s.newTestSession()
			if err := s.store.Create(ctx, sess); err != nil {
				errors.Add(1)
			}
		}()
	}

	wg.Wait()

	s.Equal(int32(0), errors.Load(), "no create errors expected")

	// Verify count
	sessions, err := s.store.ListByUser(ctx, s.userID)
	s.Require().NoError(err)
	s.Len(sessions, goroutines)
}

// TestDeleteExpiredSessions verifies concurrent delete expired sessions.
func (s *PostgresStoreSuite) TestDeleteExpiredSessions() {
	ctx := context.Background()

	// Create expired sessions
	for i := 0; i < 10; i++ {
		sess := s.newTestSession()
		sess.CreatedAt = time.Now().Add(-2 * time.Hour) // Created 2 hours ago
		sess.ExpiresAt = time.Now().Add(-1 * time.Hour) // Expired 1 hour ago
		err := s.store.Create(ctx, sess)
		s.Require().NoError(err)
	}

	// Create active sessions
	for i := 0; i < 5; i++ {
		sess := s.newTestSession()
		err := s.store.Create(ctx, sess)
		s.Require().NoError(err)
	}

	// Delete expired
	deleted, err := s.store.DeleteExpiredSessions(ctx, time.Now())
	s.Require().NoError(err)
	s.Equal(10, deleted)

	// Verify only active remain
	sessions, err := s.store.ListByUser(ctx, s.userID)
	s.Require().NoError(err)
	s.Len(sessions, 5)
}

// TestNotFoundError verifies proper error handling.
func (s *PostgresStoreSuite) TestNotFoundError() {
	ctx := context.Background()

	// FindByID with non-existent ID
	_, err := s.store.FindByID(ctx, id.SessionID(uuid.New()))
	s.ErrorIs(err, sentinel.ErrNotFound)

	// Execute on non-existent session
	_, err = s.store.Execute(ctx, id.SessionID(uuid.New()),
		func(s *models.Session) error { return nil },
		func(s *models.Session) {},
	)
	s.ErrorIs(err, sentinel.ErrNotFound)

	// RevokeSessionIfActive on non-existent session
	err = s.store.RevokeSessionIfActive(ctx, id.SessionID(uuid.New()), time.Now())
	s.ErrorIs(err, sentinel.ErrNotFound)
}
