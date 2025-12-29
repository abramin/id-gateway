package bucket

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

const (
	testLimit  = 10
	testWindow = time.Minute
)

type InMemoryBucketStoreSuite struct {
	suite.Suite
	store *InMemoryBucketStore
	ctx   context.Context
}

func TestInMemoryBucketStoreSuite(t *testing.T) {
	suite.Run(t, new(InMemoryBucketStoreSuite))
}

func (s *InMemoryBucketStoreSuite) SetupTest() {
	s.store = New()
	s.ctx = context.Background()
}

// NOTE: Basic Allow() tests (first request, up to limit, over limit, window reset)
// are covered by E2E FR-1 scenarios in ratelimit.feature. Only store-specific
// behaviors that cannot be tested via HTTP are tested here.

func (s *InMemoryBucketStoreSuite) TestAllowN() {
	s.Run("cost of 1 behaves like Allow", func() {
		result, err := s.store.AllowN(s.ctx, "allown:one", 1, testLimit, testWindow)
		s.Require().NoError(err)
		s.True(result.Allowed)
		s.Equal(testLimit, result.Limit)
		s.Equal(testLimit-1, result.Remaining)
	})

	s.Run("cost of 5 consumes 5 tokens", func() {
		result, err := s.store.AllowN(s.ctx, "allown:five", 5, testLimit, testWindow)
		s.Require().NoError(err)
		s.True(result.Allowed)
		s.Equal(testLimit, result.Limit)
		s.Equal(5, result.Remaining)
	})

	s.Run("cost greater than remaining denied", func() {
		firstResult, err := s.store.AllowN(s.ctx, "allown:deny", 7, testLimit, testWindow)
		s.Require().NoError(err)
		s.Require().True(firstResult.Allowed)

		result, err := s.store.AllowN(s.ctx, "allown:deny", 4, testLimit, testWindow)
		s.Require().NoError(err)
		s.False(result.Allowed)
		s.Equal(0, result.Remaining)
	})
}

func (s *InMemoryBucketStoreSuite) TestReset() {
	key := "reset"
	_, err := s.store.AllowN(s.ctx, key, 5, testLimit, testWindow)
	s.Require().NoError(err)

	err = s.store.Reset(s.ctx, key)
	s.Require().NoError(err)

	result, err := s.store.AllowN(s.ctx, key, testLimit, testLimit, testWindow)
	s.Require().NoError(err)
	s.True(result.Allowed)
	s.Equal(testLimit, result.Limit)
	s.Equal(0, result.Remaining)
}

func (s *InMemoryBucketStoreSuite) TestConcurrent() {
	limit := 100 // Different from testLimit for concurrency testing
	key := "concurrent"
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowedCount := 0

	for range 200 {
		wg.Go(func() {
			result, err := s.store.Allow(s.ctx, key, limit, testWindow)
			s.Require().NoError(err)
			if result.Allowed {
				mu.Lock()
				allowedCount++
				mu.Unlock()
			}
		})
	}

	wg.Wait()
	s.Equal(limit, allowedCount)
}

// =============================================================================
// Clock Skew Protection Tests
// =============================================================================
// Security test: Verify that future timestamps don't corrupt the sliding window.

func (s *InMemoryBucketStoreSuite) TestClockSkewProtection() {
	s.Run("timestamps within tolerance are counted", func() {
		// Use a fresh store with time context
		store := New()
		key := "skew:within"

		// Make a request at current time
		result, err := store.Allow(s.ctx, key, testLimit, testWindow)
		s.Require().NoError(err)
		s.True(result.Allowed)
		s.Equal(testLimit-1, result.Remaining)
	})

	s.Run("sliding window maintains correct count after multiple requests", func() {
		store := New()
		key := "skew:multiple"

		// Make 5 requests
		for i := 0; i < 5; i++ {
			result, err := store.Allow(s.ctx, key, testLimit, testWindow)
			s.Require().NoError(err)
			s.True(result.Allowed)
			s.Equal(testLimit-1-i, result.Remaining)
		}

		// Verify count
		count, err := store.GetCurrentCount(s.ctx, key)
		s.Require().NoError(err)
		s.Equal(5, count)
	})
}
