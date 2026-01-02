package authlockout

import (
	"context"
	"testing"
	"time"

	"credo/internal/ratelimit/models"

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
		s.NoError(err)
		s.Nil(record)
	})

	s.Run("existing record is returned", func() {
		fixedTime := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
		identifier := "test-user"

		// Create record via GetOrCreate
		_, err := s.store.GetOrCreate(ctx, identifier, fixedTime)
		s.NoError(err)

		// Get should return the record
		record, err := s.store.Get(ctx, identifier)
		s.NoError(err)
		s.NotNil(record)
		s.Equal(identifier, record.Identifier)
		s.Equal(0, record.FailureCount, "GetOrCreate creates with zero counts")
		s.Equal(fixedTime, record.LastFailureAt)
	})
}

func (s *InMemoryAuthLockoutStoreSuite) TestGetOrCreate() {
	ctx := context.Background()

	s.Run("creates new record with zero counts", func() {
		now := time.Now()
		identifier := "new-user"

		record, err := s.store.GetOrCreate(ctx, identifier, now)
		s.NoError(err)
		s.NotNil(record)
		s.Equal(identifier, record.Identifier)
		s.Equal(0, record.FailureCount)
		s.Equal(0, record.DailyFailures)
		s.Nil(record.LockedUntil)
		s.False(record.RequiresCaptcha)
	})

	s.Run("returns existing record without modification", func() {
		now := time.Now()
		identifier := "existing-user"

		// Create initial record
		_, err := s.store.GetOrCreate(ctx, identifier, now)
		s.NoError(err)

		// Modify via Update
		record, _ := s.store.Get(ctx, identifier)
		record.FailureCount = 5
		err = s.store.Update(ctx, record)
		s.NoError(err)

		// GetOrCreate should return existing without modification
		record2, err := s.store.GetOrCreate(ctx, identifier, now.Add(time.Hour))
		s.NoError(err)
		s.Equal(5, record2.FailureCount, "should return existing record unchanged")
	})
}

func (s *InMemoryAuthLockoutStoreSuite) TestClear() {
	ctx := context.Background()

	s.Run("clearing existing record removes it", func() {
		identifier := "to-be-cleared"
		now := time.Now()

		_, err := s.store.GetOrCreate(ctx, identifier, now)
		s.NoError(err)

		record, err := s.store.Get(ctx, identifier)
		s.NoError(err)
		s.NotNil(record)

		err = s.store.Clear(ctx, identifier)
		s.NoError(err)

		record, err = s.store.Get(ctx, identifier)
		s.NoError(err)
		s.Nil(record)
	})

	s.Run("clearing missing record is no-op", func() {
		err := s.store.Clear(ctx, "never-existed")
		s.NoError(err)
	})
}

func (s *InMemoryAuthLockoutStoreSuite) TestUpdate() {
	ctx := context.Background()

	s.Run("update modifies existing record", func() {
		identifier := "updatable-user"
		now := time.Now()

		_, err := s.store.GetOrCreate(ctx, identifier, now)
		s.NoError(err)

		updatedRecord := &models.AuthLockout{
			Identifier:      identifier,
			FailureCount:    5,
			DailyFailures:   10,
			RequiresCaptcha: true,
		}
		err = s.store.Update(ctx, updatedRecord)
		s.NoError(err)

		record, err := s.store.Get(ctx, identifier)
		s.NoError(err)
		s.Equal(5, record.FailureCount)
		s.Equal(10, record.DailyFailures)
		s.True(record.RequiresCaptcha)
	})
}

func (s *InMemoryAuthLockoutStoreSuite) TestResetFailureCount() {
	ctx := context.Background()
	identifier1 := "old-failure-user"
	identifier2 := "recent-failure-user"

	// Create records at different times
	oldTime := time.Now().Add(-30 * time.Minute)
	recentTime := time.Now().Add(-5 * time.Minute)

	// Create and set up old record
	record1, _ := s.store.GetOrCreate(ctx, identifier1, oldTime)
	record1.FailureCount = 1
	s.store.Update(ctx, record1)

	// Create and set up recent record
	record2, _ := s.store.GetOrCreate(ctx, identifier2, recentTime)
	record2.FailureCount = 1
	s.store.Update(ctx, record2)

	// Reset with cutoff between old and recent
	cutoff := time.Now().Add(-15 * time.Minute)
	resetCount, err := s.store.ResetFailureCount(ctx, cutoff)
	s.NoError(err)
	s.Equal(1, resetCount, "should reset 1 record's failure count")

	record1, _ = s.store.Get(ctx, identifier1)
	s.Equal(0, record1.FailureCount, "old failure user's count should be reset")

	record2, _ = s.store.Get(ctx, identifier2)
	s.Equal(1, record2.FailureCount, "recent failure user's count should remain unchanged")
}

func (s *InMemoryAuthLockoutStoreSuite) TestResetDailyFailures() {
	ctx := context.Background()
	identifier1 := "user-one"
	identifier2 := "user-two"

	oldTime := time.Now().Add(-30 * time.Hour)
	recentTime := time.Now()

	// Create and set up old record
	record1, _ := s.store.GetOrCreate(ctx, identifier1, oldTime)
	record1.DailyFailures = 1
	s.store.Update(ctx, record1)

	// Create and set up recent record
	record2, _ := s.store.GetOrCreate(ctx, identifier2, recentTime)
	record2.DailyFailures = 1
	s.store.Update(ctx, record2)

	// Reset with cutoff at 24h ago
	cutoff := time.Now().Add(-24 * time.Hour)
	resetCount, err := s.store.ResetDailyFailures(ctx, cutoff)
	s.NoError(err)
	s.Equal(1, resetCount, "should reset daily failures for 1 record")

	record1, _ = s.store.Get(ctx, identifier1)
	s.Equal(0, record1.DailyFailures, "user one daily failures should be reset")

	record2, _ = s.store.Get(ctx, identifier2)
	s.Equal(1, record2.DailyFailures, "user two daily failures should not be reset")
}
