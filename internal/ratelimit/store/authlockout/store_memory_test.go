package authlockout

import (
	"context"
	"testing"
	"time"

	"credo/internal/ratelimit/models"
	requesttime "credo/pkg/platform/middleware/requesttime"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type InMemoryAuthLockoutStoreSuite struct {
	suite.Suite
	store *InMemoryAuthLockoutStore
}

func TestInMemoryAuthLockoutStoreSuite(t *testing.T) {
	suite.Run(t, new(InMemoryAuthLockoutStoreSuite))
}

func (s *InMemoryAuthLockoutStoreSuite) SetupTest() {
	s.store = New()
}

func (s *InMemoryAuthLockoutStoreSuite) TestGet() {
	ctx := context.Background()

	s.Run("missing identifier returns nil without error", func() {
		record, err := s.store.Get(ctx, "unknown-id")
		require.NoError(s.T(), err)
		assert.Nil(s.T(), record)
	})

	s.Run("existing record is returned without mutation", func() {
		// Setup: create a record via RecordFailure
		fixedTime := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
		ctx := requesttime.WithTime(context.Background(), fixedTime)
		identifier := "test-user"

		_, err := s.store.RecordFailure(ctx, identifier)
		require.NoError(s.T(), err)

		// Get should return the record without mutating it
		record, err := s.store.Get(ctx, identifier)
		require.NoError(s.T(), err)
		require.NotNil(s.T(), record)
		assert.Equal(s.T(), identifier, record.Identifier)
		assert.Equal(s.T(), 1, record.FailureCount)
		assert.Equal(s.T(), fixedTime, record.LastFailureAt)
	})
}

func (s *InMemoryAuthLockoutStoreSuite) TestRecordFailure() {
	s.Run("first failure creates record with counters initialized to 1", func() {
		fixedTime := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
		ctx := requesttime.WithTime(context.Background(), fixedTime)
		identifier := "new-user"

		record, err := s.store.RecordFailure(ctx, identifier)
		require.NoError(s.T(), err)
		require.NotNil(s.T(), record)

		assert.Equal(s.T(), identifier, record.Identifier)
		assert.Equal(s.T(), 1, record.FailureCount)
		assert.Equal(s.T(), 1, record.DailyFailures)
		assert.Equal(s.T(), fixedTime, record.LastFailureAt)
		assert.Nil(s.T(), record.LockedUntil)
		assert.False(s.T(), record.RequiresCaptcha)
	})

	s.Run("subsequent failures increment counters", func() {
		firstTime := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
		secondTime := time.Date(2024, 6, 15, 12, 1, 0, 0, time.UTC)
		identifier := "repeat-offender"

		// First failure
		ctx1 := requesttime.WithTime(context.Background(), firstTime)
		record1, err := s.store.RecordFailure(ctx1, identifier)
		require.NoError(s.T(), err)
		assert.Equal(s.T(), 1, record1.FailureCount)
		assert.Equal(s.T(), firstTime, record1.LastFailureAt)

		// Second failure - different time
		ctx2 := requesttime.WithTime(context.Background(), secondTime)
		record2, err := s.store.RecordFailure(ctx2, identifier)
		require.NoError(s.T(), err)
		assert.Equal(s.T(), 2, record2.FailureCount)
		assert.Equal(s.T(), 2, record2.DailyFailures)
		assert.Equal(s.T(), secondTime, record2.LastFailureAt)
	})
}

func (s *InMemoryAuthLockoutStoreSuite) TestClear() {
	ctx := context.Background()

	s.Run("clearing existing record removes it", func() {
		identifier := "to-be-cleared"

		// Create record
		_, err := s.store.RecordFailure(ctx, identifier)
		require.NoError(s.T(), err)

		// Verify it exists
		record, err := s.store.Get(ctx, identifier)
		require.NoError(s.T(), err)
		require.NotNil(s.T(), record)

		// Clear it
		err = s.store.Clear(ctx, identifier)
		require.NoError(s.T(), err)

		// Verify it's gone
		record, err = s.store.Get(ctx, identifier)
		require.NoError(s.T(), err)
		assert.Nil(s.T(), record)
	})

	s.Run("clearing missing record is no-op", func() {
		err := s.store.Clear(ctx, "never-existed")
		require.NoError(s.T(), err)
	})
}

func (s *InMemoryAuthLockoutStoreSuite) TestIsLocked() {
	ctx := context.Background()

	s.Run("unlocked when no record exists", func() {
		locked, lockedUntil, err := s.store.IsLocked(ctx, "unknown")
		require.NoError(s.T(), err)
		assert.False(s.T(), locked)
		assert.Nil(s.T(), lockedUntil)
	})

	s.Run("locked when LockedUntil is in the future", func() {
		identifier := "locked-user"
		futureTime := time.Now().Add(10 * time.Minute)

		// Create and update record with lock
		_, err := s.store.RecordFailure(ctx, identifier)
		require.NoError(s.T(), err)

		record, _ := s.store.Get(ctx, identifier)
		record.LockedUntil = &futureTime
		err = s.store.Update(ctx, record)
		require.NoError(s.T(), err)

		// Check lock status
		locked, lockedUntil, err := s.store.IsLocked(ctx, identifier)
		require.NoError(s.T(), err)
		assert.True(s.T(), locked)
		assert.Equal(s.T(), futureTime, *lockedUntil)
	})

	s.Run("unlocked when LockedUntil is in the past", func() {
		identifier := "expired-lock-user"
		pastTime := time.Now().Add(-10 * time.Minute)

		// Create and update record with expired lock
		_, err := s.store.RecordFailure(ctx, identifier)
		require.NoError(s.T(), err)

		record, _ := s.store.Get(ctx, identifier)
		record.LockedUntil = &pastTime
		err = s.store.Update(ctx, record)
		require.NoError(s.T(), err)

		// Check lock status - should be unlocked since lock expired
		locked, _, err := s.store.IsLocked(ctx, identifier)
		require.NoError(s.T(), err)
		assert.False(s.T(), locked)
	})
}

func (s *InMemoryAuthLockoutStoreSuite) TestUpdate() {
	ctx := context.Background()

	s.Run("update modifies existing record", func() {
		identifier := "updatable-user"

		// Create record
		_, err := s.store.RecordFailure(ctx, identifier)
		require.NoError(s.T(), err)

		// Update with new values
		updatedRecord := &models.AuthLockout{
			Identifier:      identifier,
			FailureCount:    5,
			DailyFailures:   10,
			RequiresCaptcha: true,
		}
		err = s.store.Update(ctx, updatedRecord)
		require.NoError(s.T(), err)

		// Verify update took effect
		record, err := s.store.Get(ctx, identifier)
		require.NoError(s.T(), err)
		assert.Equal(s.T(), 5, record.FailureCount)
		assert.Equal(s.T(), 10, record.DailyFailures)
		assert.True(s.T(), record.RequiresCaptcha)
	})
}
