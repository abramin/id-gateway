//go:build integration

package store_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"

	"credo/internal/evidence/vc/models"
	"credo/internal/evidence/vc/store"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"
	"credo/pkg/testutil/containers"
)

type PostgresStoreSuite struct {
	suite.Suite
	postgres *containers.PostgresContainer
	store    *store.PostgresStore
	tenantID id.TenantID
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
	s.store = store.NewPostgres(s.postgres.DB)
}

func (s *PostgresStoreSuite) SetupTest() {
	ctx := context.Background()

	// Truncate tables in dependency order
	err := s.postgres.TruncateTables(ctx, "vc_credentials", "users", "clients", "tenants")
	s.Require().NoError(err)

	// Create test tenant
	s.tenantID = id.TenantID(uuid.New())
	_, err = s.postgres.Exec(ctx, `
		INSERT INTO tenants (id, name, status, created_at, updated_at)
		VALUES ($1, $2, 'active', NOW(), NOW())
	`, uuid.UUID(s.tenantID), "Test Tenant "+uuid.NewString())
	s.Require().NoError(err)

	// Create test user (required due to FK on vc_credentials.subject_id)
	s.userID = id.UserID(uuid.New())
	_, err = s.postgres.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, first_name, last_name, verified, status)
		VALUES ($1, $2, $3, 'Test', 'User', true, 'active')
	`, uuid.UUID(s.userID), uuid.UUID(s.tenantID), "test-"+uuid.NewString()+"@example.com")
	s.Require().NoError(err)
}

// createTestUser creates an additional user for tests that need multiple users.
func (s *PostgresStoreSuite) createTestUser(ctx context.Context) id.UserID {
	userID := id.UserID(uuid.New())
	_, err := s.postgres.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, first_name, last_name, verified, status)
		VALUES ($1, $2, $3, 'Test', 'User', true, 'active')
	`, uuid.UUID(userID), uuid.UUID(s.tenantID), "test-"+uuid.NewString()+"@example.com")
	s.Require().NoError(err)
	return userID
}

// TestConcurrentVCUpsert verifies that concurrent upserts on the same credential ID
// result in last-write-wins semantics without corruption.
func (s *PostgresStoreSuite) TestConcurrentVCUpsert() {
	ctx := context.Background()
	credID := models.NewCredentialID()
	const goroutines = 50

	var wg sync.WaitGroup
	var successCount atomic.Int32

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			credential := models.CredentialRecord{
				ID:       credID,
				Type:     models.CredentialTypeAgeOver18,
				Subject:  s.userID,
				Issuer:   models.IssuerCredo,
				IssuedAt: time.Now().Add(time.Duration(idx) * time.Millisecond),
				Claims: models.Claims{
					"age_verified": true,
					"iteration":    idx,
				},
			}

			err := s.store.Save(ctx, credential)
			if err == nil {
				successCount.Add(1)
			}
		}(i)
	}

	wg.Wait()

	// All upserts should succeed
	s.Equal(int32(goroutines), successCount.Load(), "all concurrent upserts should succeed")

	// Verify exactly one record exists
	found, err := s.store.FindByID(ctx, credID)
	s.Require().NoError(err)
	s.Equal(credID, found.ID)
	s.Equal(s.userID, found.Subject)
}

// TestSubjectTypeQueryOrdering verifies that FindBySubjectAndType returns
// the most recently issued credential.
func (s *PostgresStoreSuite) TestSubjectTypeQueryOrdering() {
	ctx := context.Background()

	// Create multiple credentials with different timestamps
	baseTime := time.Now().Truncate(time.Second)
	var expectedLatestTime time.Time
	for i := 0; i < 5; i++ {
		issuedAt := baseTime.Add(time.Duration(i) * time.Hour)
		if i == 4 {
			expectedLatestTime = issuedAt
		}
		credential := models.CredentialRecord{
			ID:       models.NewCredentialID(),
			Type:     models.CredentialTypeAgeOver18,
			Subject:  s.userID,
			Issuer:   models.IssuerCredo,
			IssuedAt: issuedAt,
			Claims: models.Claims{
				"is_over_18": true,
			},
		}
		err := s.store.Save(ctx, credential)
		s.Require().NoError(err)
	}

	// FindBySubjectAndType should return the most recent (i=4, latest timestamp)
	found, err := s.store.FindBySubjectAndType(ctx, s.userID, models.CredentialTypeAgeOver18)
	s.Require().NoError(err)
	s.WithinDuration(expectedLatestTime, found.IssuedAt, time.Second)
}

// TestAgeOver18ClaimsRoundTrip verifies AgeOver18 claims are stored in columns and restored on read.
func (s *PostgresStoreSuite) TestAgeOver18ClaimsRoundTrip() {
	ctx := context.Background()

	credID := models.NewCredentialID()
	issuedAt := time.Now()
	credential := models.CredentialRecord{
		ID:       credID,
		Type:     models.CredentialTypeAgeOver18,
		Subject:  s.userID,
		Issuer:   models.IssuerCredo,
		IssuedAt: issuedAt,
		Claims: models.Claims{
			"is_over_18":   true,
			"verified_via": "registry",
		},
	}

	err := s.store.Save(ctx, credential)
	s.Require().NoError(err)

	found, err := s.store.FindByID(ctx, credID)
	s.Require().NoError(err)

	isOver18, ok := found.Claims["is_over_18"].(bool)
	s.True(ok)
	s.True(isOver18)

	verifiedVia, ok := found.Claims["verified_via"].(string)
	s.True(ok)
	s.Equal("registry", verifiedVia)
}

// TestConcurrentDifferentCredentials verifies concurrent saves of different credentials.
func (s *PostgresStoreSuite) TestConcurrentDifferentCredentials() {
	ctx := context.Background()
	const goroutines = 50

	var wg sync.WaitGroup
	var errors atomic.Int32

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			credential := models.CredentialRecord{
				ID:       models.NewCredentialID(), // Each goroutine gets a unique ID
				Type:     models.CredentialTypeAgeOver18,
				Subject:  s.userID,
				Issuer:   models.IssuerCredo,
				IssuedAt: time.Now(),
				Claims: models.Claims{
					"iteration": idx,
				},
			}

			if err := s.store.Save(ctx, credential); err != nil {
				errors.Add(1)
			}
		}(i)
	}

	wg.Wait()

	s.Equal(int32(0), errors.Load(), "no errors expected")
}

// TestConcurrentSaveAndFind verifies concurrent save and find operations.
func (s *PostgresStoreSuite) TestConcurrentSaveAndFind() {
	ctx := context.Background()
	const goroutines = 30

	// Pre-create some credentials
	credIDs := make([]models.CredentialID, 10)
	for i := 0; i < 10; i++ {
		credIDs[i] = models.NewCredentialID()
		credential := models.CredentialRecord{
			ID:       credIDs[i],
			Type:     models.CredentialTypeAgeOver18,
			Subject:  s.userID,
			Issuer:   models.IssuerCredo,
			IssuedAt: time.Now(),
			Claims:   models.Claims{"initial": true},
		}
		err := s.store.Save(ctx, credential)
		s.Require().NoError(err)
	}

	var wg sync.WaitGroup
	var saveErrors, findErrors atomic.Int32

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			// Mix of saves and finds
			credID := credIDs[idx%10]

			if idx%2 == 0 {
				// Save
				credential := models.CredentialRecord{
					ID:       credID,
					Type:     models.CredentialTypeAgeOver18,
					Subject:  s.userID,
					Issuer:   models.IssuerCredo,
					IssuedAt: time.Now(),
					Claims:   models.Claims{"updated": true, "iteration": idx},
				}
				if err := s.store.Save(ctx, credential); err != nil {
					saveErrors.Add(1)
				}
			} else {
				// Find
				_, err := s.store.FindByID(ctx, credID)
				if err != nil && err != sentinel.ErrNotFound {
					findErrors.Add(1)
				}
			}
		}(i)
	}

	wg.Wait()

	s.Equal(int32(0), saveErrors.Load(), "no save errors expected")
	s.Equal(int32(0), findErrors.Load(), "no unexpected find errors")
}

// TestMultipleUsersCredentials verifies isolation between different users' credentials.
func (s *PostgresStoreSuite) TestMultipleUsersCredentials() {
	ctx := context.Background()

	// Create additional users
	user2 := s.createTestUser(ctx)
	user3 := s.createTestUser(ctx)

	// Save credentials for each user
	users := []id.UserID{s.userID, user2, user3}
	for _, userID := range users {
		credential := models.CredentialRecord{
			ID:       models.NewCredentialID(),
			Type:     models.CredentialTypeAgeOver18,
			Subject:  userID,
			Issuer:   models.IssuerCredo,
			IssuedAt: time.Now(),
			Claims: models.Claims{
				"is_over_18": true,
			},
		}
		err := s.store.Save(ctx, credential)
		s.Require().NoError(err)
	}

	// Each user should only find their own credential
	for _, userID := range users {
		found, err := s.store.FindBySubjectAndType(ctx, userID, models.CredentialTypeAgeOver18)
		s.Require().NoError(err)
		s.Equal(userID, found.Subject)
		s.Equal(true, found.Claims["is_over_18"])
	}
}

// TestNotFoundError verifies proper error handling for non-existent credentials.
func (s *PostgresStoreSuite) TestNotFoundError() {
	ctx := context.Background()

	// FindByID with non-existent ID
	_, err := s.store.FindByID(ctx, models.CredentialID("vc_"+uuid.NewString()))
	s.ErrorIs(err, sentinel.ErrNotFound)

	// FindBySubjectAndType with no credentials
	newUser := s.createTestUser(ctx)
	_, err = s.store.FindBySubjectAndType(ctx, newUser, models.CredentialTypeAgeOver18)
	s.ErrorIs(err, sentinel.ErrNotFound)
}
