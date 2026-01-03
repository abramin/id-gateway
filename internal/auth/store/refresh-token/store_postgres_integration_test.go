//go:build integration

package refreshtoken_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"

	"credo/internal/auth/models"
	refreshtoken "credo/internal/auth/store/refresh-token"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/sentinel"
	"credo/pkg/testutil/containers"
)

type PostgresStoreSuite struct {
	suite.Suite
	postgres  *containers.PostgresContainer
	store     *refreshtoken.PostgresStore
	sessionID id.SessionID
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
	s.store = refreshtoken.NewPostgres(s.postgres.DB)
}

func (s *PostgresStoreSuite) SetupTest() {
	ctx := context.Background()

	err := s.postgres.TruncateTables(ctx, "refresh_tokens", "sessions", "users", "clients", "tenants")
	s.Require().NoError(err)

	// Create tenant -> client -> user -> session chain for FK constraints
	tenantID := uuid.New()
	_, err = s.postgres.Exec(ctx, `
		INSERT INTO tenants (id, name, status, created_at, updated_at)
		VALUES ($1, 'Test Tenant', 'active', NOW(), NOW())
	`, tenantID)
	s.Require().NoError(err)

	clientID := uuid.New()
	_, err = s.postgres.Exec(ctx, `
		INSERT INTO clients (id, tenant_id, name, oauth_client_id, redirect_uris, allowed_grants, allowed_scopes, status, created_at, updated_at)
		VALUES ($1, $2, 'Test Client', $3, '[]', '["authorization_code"]', '["openid"]', 'active', NOW(), NOW())
	`, clientID, tenantID, "client-"+uuid.NewString())
	s.Require().NoError(err)

	userID := uuid.New()
	_, err = s.postgres.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, first_name, last_name, verified, status)
		VALUES ($1, $2, $3, 'Test', 'User', true, 'active')
	`, userID, tenantID, "test-"+uuid.NewString()+"@example.com")
	s.Require().NoError(err)

	s.sessionID = id.SessionID(uuid.New())
	_, err = s.postgres.Exec(ctx, `
		INSERT INTO sessions (id, user_id, client_id, tenant_id, requested_scope, status, device_id, created_at, expires_at, last_seen_at)
		VALUES ($1, $2, $3, $4, '["openid"]', 'active', $5, NOW(), NOW() + INTERVAL '1 day', NOW())
	`, uuid.UUID(s.sessionID), userID, clientID, tenantID, uuid.NewString())
	s.Require().NoError(err)
}

func (s *PostgresStoreSuite) newTestToken() *models.RefreshTokenRecord {
	now := time.Now()
	return &models.RefreshTokenRecord{
		ID:        uuid.New(),
		Token:     uuid.NewString(),
		SessionID: s.sessionID,
		ExpiresAt: now.Add(24 * time.Hour),
		Used:      false,
		CreatedAt: now,
	}
}

// TestConcurrentTokenUse verifies that concurrent use of the same token
// results in exactly one success due to FOR UPDATE locking.
func (s *PostgresStoreSuite) TestConcurrentTokenUse() {
	ctx := context.Background()

	token := s.newTestToken()
	err := s.store.Create(ctx, token)
	s.Require().NoError(err)

	const goroutines = 50
	var wg sync.WaitGroup
	var successCount atomic.Int32
	var alreadyUsedCount atomic.Int32

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			_, err := s.store.Execute(ctx, token.Token,
				func(r *models.RefreshTokenRecord) error {
					if r.Used {
						return dErrors.New(dErrors.CodeForbidden, "token already used")
					}
					if r.ExpiresAt.Before(time.Now()) {
						return dErrors.New(dErrors.CodeForbidden, "token expired")
					}
					return nil
				},
				func(r *models.RefreshTokenRecord) {
					r.Used = true
					now := time.Now()
					r.LastRefreshedAt = &now
				},
			)
			if err == nil {
				successCount.Add(1)
			} else {
				alreadyUsedCount.Add(1)
			}
		}()
	}

	wg.Wait()

	// Exactly one should succeed
	s.Equal(int32(1), successCount.Load(), "exactly one token use should succeed")
	s.Equal(int32(goroutines-1), alreadyUsedCount.Load(), "others should see token already used")

	// Verify token is marked as used
	found, err := s.store.Find(ctx, token.Token)
	s.Require().NoError(err)
	s.True(found.Used)
}

// TestTokenRotationRace verifies concurrent token creation and validation.
func (s *PostgresStoreSuite) TestTokenRotationRace() {
	ctx := context.Background()
	const goroutines = 30

	var wg sync.WaitGroup
	var createErrors atomic.Int32

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			token := s.newTestToken()
			if err := s.store.Create(ctx, token); err != nil {
				createErrors.Add(1)
			}
		}()
	}

	wg.Wait()

	s.Equal(int32(0), createErrors.Load(), "no create errors expected")

	// Find active token for session should work
	found, err := s.store.FindBySessionID(ctx, s.sessionID, time.Now())
	s.Require().NoError(err)
	s.NotNil(found)
	s.False(found.Used)
}

// TestDeleteExpiredTokensConcurrency verifies delete expired behavior.
func (s *PostgresStoreSuite) TestDeleteExpiredTokensConcurrency() {
	ctx := context.Background()

	// Create expired tokens
	for i := 0; i < 10; i++ {
		token := s.newTestToken()
		token.ExpiresAt = time.Now().Add(-1 * time.Hour)
		err := s.store.Create(ctx, token)
		s.Require().NoError(err)
	}

	// Create active tokens
	for i := 0; i < 5; i++ {
		token := s.newTestToken()
		err := s.store.Create(ctx, token)
		s.Require().NoError(err)
	}

	deleted, err := s.store.DeleteExpiredTokens(ctx, time.Now())
	s.Require().NoError(err)
	s.Equal(10, deleted)

	// Active token should still be findable
	found, err := s.store.FindBySessionID(ctx, s.sessionID, time.Now())
	s.Require().NoError(err)
	s.NotNil(found)
}

// TestExecuteAtomicity verifies validation errors prevent mutation.
func (s *PostgresStoreSuite) TestExecuteAtomicity() {
	ctx := context.Background()

	token := s.newTestToken()
	err := s.store.Create(ctx, token)
	s.Require().NoError(err)

	validationErr := dErrors.New(dErrors.CodeForbidden, "intentional failure")

	// Execute with failing validation
	_, err = s.store.Execute(ctx, token.Token,
		func(r *models.RefreshTokenRecord) error {
			return validationErr
		},
		func(r *models.RefreshTokenRecord) {
			r.Used = true // Should NOT be applied
		},
	)

	s.Error(err)

	// Verify token unchanged
	found, err := s.store.Find(ctx, token.Token)
	s.Require().NoError(err)
	s.False(found.Used, "token should not be marked as used")
}

// TestNotFoundError verifies proper error handling.
func (s *PostgresStoreSuite) TestNotFoundError() {
	ctx := context.Background()

	// Find non-existent token
	_, err := s.store.Find(ctx, "non-existent-token")
	s.ErrorIs(err, sentinel.ErrNotFound)

	// Execute on non-existent token
	_, err = s.store.Execute(ctx, "non-existent-token",
		func(r *models.RefreshTokenRecord) error { return nil },
		func(r *models.RefreshTokenRecord) {},
	)
	s.ErrorIs(err, sentinel.ErrNotFound)

	// Delete by non-existent session
	err = s.store.DeleteBySessionID(ctx, id.SessionID(uuid.New()))
	s.ErrorIs(err, sentinel.ErrNotFound)
}
