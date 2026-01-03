//go:build integration

package authorizationcode_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"

	"credo/internal/auth/models"
	authcode "credo/internal/auth/store/authorization-code"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/sentinel"
	"credo/pkg/testutil/containers"
)

type PostgresStoreSuite struct {
	suite.Suite
	postgres  *containers.PostgresContainer
	store     *authcode.PostgresStore
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
	s.store = authcode.NewPostgres(s.postgres.DB)
}

func (s *PostgresStoreSuite) SetupTest() {
	ctx := context.Background()

	err := s.postgres.TruncateTables(ctx, "authorization_codes", "sessions", "users", "clients", "tenants")
	s.Require().NoError(err)

	// Create FK chain
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

func (s *PostgresStoreSuite) newTestCode() *models.AuthorizationCodeRecord {
	now := time.Now()
	return &models.AuthorizationCodeRecord{
		ID:          uuid.New(),
		Code:        uuid.NewString(),
		SessionID:   s.sessionID,
		RedirectURI: "https://example.com/callback",
		ExpiresAt:   now.Add(10 * time.Minute),
		Used:        false,
		CreatedAt:   now,
	}
}

// TestConcurrentCodeExchange verifies that concurrent code exchange attempts
// result in exactly one success.
func (s *PostgresStoreSuite) TestConcurrentCodeExchange() {
	ctx := context.Background()

	code := s.newTestCode()
	err := s.store.Create(ctx, code)
	s.Require().NoError(err)

	const goroutines = 50
	var wg sync.WaitGroup
	var successCount atomic.Int32
	var alreadyUsedCount atomic.Int32

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			_, err := s.store.Execute(ctx, code.Code,
				func(r *models.AuthorizationCodeRecord) error {
					if r.Used {
						return dErrors.New(dErrors.CodeForbidden, "code already used")
					}
					if r.ExpiresAt.Before(time.Now()) {
						return dErrors.New(dErrors.CodeForbidden, "code expired")
					}
					return nil
				},
				func(r *models.AuthorizationCodeRecord) {
					r.Used = true
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

	// Exactly one should succeed (replay attack prevention)
	s.Equal(int32(1), successCount.Load(), "exactly one code exchange should succeed")
	s.Equal(int32(goroutines-1), alreadyUsedCount.Load(), "others should see code already used")

	// Verify code is marked as used
	found, err := s.store.FindByCode(ctx, code.Code)
	s.Require().NoError(err)
	s.True(found.Used)
}

// TestCodeExpiryDuringExchange verifies expiry check within Execute.
func (s *PostgresStoreSuite) TestCodeExpiryDuringExchange() {
	ctx := context.Background()

	// Create already expired code
	code := s.newTestCode()
	code.ExpiresAt = time.Now().Add(-1 * time.Minute)
	err := s.store.Create(ctx, code)
	s.Require().NoError(err)

	expiryErr := dErrors.New(dErrors.CodeForbidden, "code expired")

	_, err = s.store.Execute(ctx, code.Code,
		func(r *models.AuthorizationCodeRecord) error {
			if r.ExpiresAt.Before(time.Now()) {
				return expiryErr
			}
			return nil
		},
		func(r *models.AuthorizationCodeRecord) {
			r.Used = true
		},
	)

	s.ErrorIs(err, expiryErr)

	// Code should NOT be marked as used
	found, err := s.store.FindByCode(ctx, code.Code)
	s.Require().NoError(err)
	s.False(found.Used)
}

// TestConcurrentCreateDifferentCodes verifies concurrent creation of different codes.
func (s *PostgresStoreSuite) TestConcurrentCreateDifferentCodes() {
	ctx := context.Background()
	const goroutines = 50

	var wg sync.WaitGroup
	var errors atomic.Int32

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			code := s.newTestCode()
			if err := s.store.Create(ctx, code); err != nil {
				errors.Add(1)
			}
		}()
	}

	wg.Wait()

	s.Equal(int32(0), errors.Load(), "no create errors expected")
}

// TestDeleteExpiredCodes verifies expired code cleanup.
func (s *PostgresStoreSuite) TestDeleteExpiredCodes() {
	ctx := context.Background()

	// Create expired codes
	for i := 0; i < 10; i++ {
		code := s.newTestCode()
		code.ExpiresAt = time.Now().Add(-1 * time.Hour)
		err := s.store.Create(ctx, code)
		s.Require().NoError(err)
	}

	// Create active codes
	activeCodes := make([]*models.AuthorizationCodeRecord, 5)
	for i := 0; i < 5; i++ {
		activeCodes[i] = s.newTestCode()
		err := s.store.Create(ctx, activeCodes[i])
		s.Require().NoError(err)
	}

	deleted, err := s.store.DeleteExpiredCodes(ctx, time.Now())
	s.Require().NoError(err)
	s.Equal(10, deleted)

	// Active codes should still be findable
	for _, code := range activeCodes {
		found, err := s.store.FindByCode(ctx, code.Code)
		s.Require().NoError(err)
		s.NotNil(found)
	}
}

// TestNotFoundError verifies proper error handling.
func (s *PostgresStoreSuite) TestNotFoundError() {
	ctx := context.Background()

	// FindByCode non-existent
	_, err := s.store.FindByCode(ctx, "non-existent-code")
	s.ErrorIs(err, sentinel.ErrNotFound)

	// Execute on non-existent code
	_, err = s.store.Execute(ctx, "non-existent-code",
		func(r *models.AuthorizationCodeRecord) error { return nil },
		func(r *models.AuthorizationCodeRecord) {},
	)
	s.ErrorIs(err, sentinel.ErrNotFound)

	// MarkUsed non-existent
	err = s.store.MarkUsed(ctx, "non-existent-code")
	s.ErrorIs(err, sentinel.ErrNotFound)
}
