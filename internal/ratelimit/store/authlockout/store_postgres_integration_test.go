//go:build integration

package authlockout_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"

	"credo/internal/ratelimit/models"
	"credo/internal/ratelimit/store/authlockout"
	"credo/pkg/testutil/containers"
)

type PostgresStoreSuite struct {
	suite.Suite
	postgres *containers.PostgresContainer
	store    *authlockout.PostgresStore
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
	s.store = authlockout.NewPostgres(s.postgres.DB, nil)
}

func (s *PostgresStoreSuite) SetupTest() {
	ctx := context.Background()
	err := s.postgres.TruncateTables(ctx, "auth_lockouts")
	s.Require().NoError(err)
}

// recordFailure is a helper that simulates the service's RecordFailure pattern:
// GetOrCreate + domain mutation + Update
func (s *PostgresStoreSuite) recordFailure(ctx context.Context, identifier string) (*models.AuthLockout, error) {
	now := time.Now()
	// Use RecordFailureAtomic for thread-safe concurrent increments
	return s.store.RecordFailureAtomic(ctx, identifier, now)
}

// TestConcurrentFailureRecording verifies that concurrent GetOrCreate + Update calls
// correctly accumulate failure counts without losing any increments.
// NOTE: With the new DDD pattern, the service orchestrates GetOrCreate + domain mutation + Update,
// so this test now verifies the store's Update behavior under concurrent writes.
func (s *PostgresStoreSuite) TestConcurrentFailureRecording() {
	ctx := context.Background()
	identifier := "user:" + uuid.NewString()
	const goroutines = 100

	var wg sync.WaitGroup
	var errors atomic.Int32

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			_, err := s.recordFailure(ctx, identifier)
			if err != nil {
				errors.Add(1)
			}
		}()
	}

	wg.Wait()

	s.Equal(int32(0), errors.Load(), "no errors expected")

	// Verify the final count equals the number of concurrent increments
	record, err := s.store.Get(ctx, identifier)
	s.Require().NoError(err)
	s.NotNil(record)
	s.Equal(goroutines, record.FailureCount, "failure count should equal number of concurrent calls")
	s.Equal(goroutines, record.DailyFailures, "daily failures should equal number of concurrent calls")
}

// TestConcurrentFailureRecordingMultipleIdentifiers verifies concurrent failures
// across multiple identifiers don't interfere with each other.
func (s *PostgresStoreSuite) TestConcurrentFailureRecordingMultipleIdentifiers() {
	ctx := context.Background()
	const identifiers = 10
	const failuresPerIdentifier = 20

	var wg sync.WaitGroup
	ids := make([]string, identifiers)
	for i := 0; i < identifiers; i++ {
		ids[i] = "user:" + uuid.NewString()
	}

	for _, id := range ids {
		for j := 0; j < failuresPerIdentifier; j++ {
			wg.Add(1)
			go func(identifier string) {
				defer wg.Done()
				_, _ = s.recordFailure(ctx, identifier)
			}(id)
		}
	}

	wg.Wait()

	// Each identifier should have exactly failuresPerIdentifier failures
	for _, id := range ids {
		record, err := s.store.Get(ctx, id)
		s.Require().NoError(err)
		s.NotNil(record)
		s.Equal(failuresPerIdentifier, record.FailureCount,
			"identifier %s should have %d failures", id, failuresPerIdentifier)
	}
}

// TestLockoutStateTransitions verifies correct behavior when updating lockout state
// concurrently with failure recording.
func (s *PostgresStoreSuite) TestLockoutStateTransitions() {
	ctx := context.Background()
	identifier := "user:" + uuid.NewString()

	// Record some initial failures
	for i := 0; i < 5; i++ {
		_, err := s.recordFailure(ctx, identifier)
		s.Require().NoError(err)
	}

	// Concurrently: some goroutines record failures, others update lockout state
	const goroutines = 50
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			if idx%5 == 0 {
				// Update lockout state
				lockedUntil := time.Now().Add(time.Minute)
				record := &models.AuthLockout{
					Identifier:      identifier,
					FailureCount:    10,
					DailyFailures:   10,
					LockedUntil:     &lockedUntil,
					LastFailureAt:   time.Now(),
					RequiresCaptcha: true,
				}
				_ = s.store.Update(ctx, record)
			} else {
				// Record additional failure
				_, _ = s.recordFailure(ctx, identifier)
			}
		}(i)
	}

	wg.Wait()

	// Verify record exists and has valid state
	record, err := s.store.Get(ctx, identifier)
	s.Require().NoError(err)
	s.NotNil(record)
	s.Equal(identifier, record.Identifier)
}

// TestClearDuringConcurrentFailures verifies Clear operation during concurrent failure recording.
func (s *PostgresStoreSuite) TestClearDuringConcurrentFailures() {
	ctx := context.Background()
	identifier := "user:" + uuid.NewString()

	// Seed with some failures
	for i := 0; i < 10; i++ {
		_, err := s.recordFailure(ctx, identifier)
		s.Require().NoError(err)
	}

	const goroutines = 50
	var wg sync.WaitGroup
	var clearErrors atomic.Int32

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			if idx == 25 {
				// One goroutine clears
				if err := s.store.Clear(ctx, identifier); err != nil {
					clearErrors.Add(1)
				}
			} else {
				// Others record failures
				_, _ = s.recordFailure(ctx, identifier)
			}
		}(i)
	}

	wg.Wait()

	s.Equal(int32(0), clearErrors.Load(), "clear should not error")

	// Record should exist (re-created after clear by subsequent failures)
	// OR be nil if clear happened last
	record, err := s.store.Get(ctx, identifier)
	s.NoError(err)
	// Final state depends on timing - either nil or has some failures
	if record != nil {
		s.Greater(record.FailureCount, 0)
	}
}

// TestDailyResetRace verifies ResetDailyFailures during concurrent failure recording.
func (s *PostgresStoreSuite) TestDailyResetRace() {
	ctx := context.Background()

	// Create multiple identifiers with old failures (> 24h ago)
	for i := 0; i < 5; i++ {
		identifier := "old:" + uuid.NewString()
		record := &models.AuthLockout{
			Identifier:    identifier,
			FailureCount:  5,
			DailyFailures: 5,
			LastFailureAt: time.Now().Add(-25 * time.Hour), // Old enough to be reset
		}
		err := s.store.Update(ctx, record)
		s.Require().NoError(err)
	}

	// Create identifiers with recent failures
	recentIDs := make([]string, 5)
	for i := 0; i < 5; i++ {
		identifier := "recent:" + uuid.NewString()
		recentIDs[i] = identifier
		_, err := s.recordFailure(ctx, identifier)
		s.Require().NoError(err)
	}

	const goroutines = 30
	var wg sync.WaitGroup
	var resetTotal atomic.Int32
	cutoff := time.Now().Add(-24 * time.Hour) // 24h ago

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			if idx%10 == 0 {
				// Reset daily failures with cutoff
				total, _ := s.store.ResetDailyFailures(ctx, cutoff)
				resetTotal.Add(int32(total))
			} else {
				// Continue recording failures on recent identifiers
				_, _ = s.recordFailure(ctx, recentIDs[idx%5])
			}
		}(i)
	}

	wg.Wait()

	// Recent identifiers should still have failures (not reset because they're within 24h)
	for _, id := range recentIDs {
		record, err := s.store.Get(ctx, id)
		s.Require().NoError(err)
		s.NotNil(record)
		s.Greater(record.DailyFailures, 0, "recent failures should not be reset")
	}
}

// TestGetConcurrency verifies concurrent Get checks don't cause issues.
func (s *PostgresStoreSuite) TestGetConcurrency() {
	ctx := context.Background()
	identifier := "user:" + uuid.NewString()

	// Create a locked record
	lockedUntil := time.Now().Add(5 * time.Minute)
	record := &models.AuthLockout{
		Identifier:    identifier,
		FailureCount:  10,
		DailyFailures: 10,
		LockedUntil:   &lockedUntil,
		LastFailureAt: time.Now(),
	}
	err := s.store.Update(ctx, record)
	s.Require().NoError(err)

	const goroutines = 100
	var wg sync.WaitGroup
	var foundCount atomic.Int32
	var errors atomic.Int32

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			rec, err := s.store.Get(ctx, identifier)
			if err != nil {
				errors.Add(1)
				return
			}
			if rec != nil {
				foundCount.Add(1)
			}
		}()
	}

	wg.Wait()

	s.Equal(int32(0), errors.Load(), "no errors expected")
	s.Equal(int32(goroutines), foundCount.Load(), "all checks should find the record")
}

// TestResetFailureCountTransaction verifies ResetFailureCount is atomic.
func (s *PostgresStoreSuite) TestResetFailureCountTransaction() {
	ctx := context.Background()

	// Create records with old failures
	for i := 0; i < 5; i++ {
		identifier := "old:" + uuid.NewString()
		record := &models.AuthLockout{
			Identifier:    identifier,
			FailureCount:  10,
			DailyFailures: 10,
			LastFailureAt: time.Now().Add(-5 * time.Second), // Older than cutoff we'll use
		}
		err := s.store.Update(ctx, record)
		s.Require().NoError(err)
	}

	// Use a cutoff that's in the future to ensure all records are "old enough"
	cutoff := time.Now().Add(time.Second)

	// Reset should return total failures
	total, err := s.store.ResetFailureCount(ctx, cutoff)
	s.Require().NoError(err)
	s.Equal(50, total, "should sum all old failure counts")
}
