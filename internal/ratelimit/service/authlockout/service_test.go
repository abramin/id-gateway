package authlockout

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"credo/internal/ratelimit/config"
	"credo/internal/ratelimit/models"
	rwauthlockoutStore "credo/internal/ratelimit/store/authlockout"
	"credo/pkg/requestcontext"
)

// =============================================================================
// AuthLockout Service Security Test Suite
// =============================================================================
// Justification: Security tests verify timing-consistent responses to prevent
// username enumeration and proper handling of daily failure counters.

type AuthLockoutServiceSecuritySuite struct {
	suite.Suite
	store   *rwauthlockoutStore.InMemoryAuthLockoutStore
	service *Service
	config  *config.AuthLockoutConfig
}

func TestAuthLockoutServiceSecuritySuite(t *testing.T) {
	suite.Run(t, new(AuthLockoutServiceSecuritySuite))
}

func (s *AuthLockoutServiceSecuritySuite) SetupTest() {
	cfg := config.DefaultConfig().AuthLockout
	s.config = &cfg
	s.store = rwauthlockoutStore.New()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var err error
	s.service, err = New(
		s.store,
		WithLogger(logger),
		WithConfig(s.config),
	)
	s.Require().NoError(err)
}

// =============================================================================
// Username Enumeration Timing Tests (Security)
// =============================================================================
// Security test: Verify consistent response structure for existing vs non-existing
// accounts to prevent timing-based username enumeration.

func (s *AuthLockoutServiceSecuritySuite) TestUsernameEnumerationPrevention() {
	ctx := context.Background()

	s.Run("response structure identical for new vs existing identifier", func() {
		// Check for an identifier that has never been seen
		newResult, err := s.service.Check(ctx, "never-seen-user@example.com", "192.168.1.1")
		s.NoError(err)

		// Record a failure for an existing identifier
		_, err = s.service.RecordFailure(ctx, "existing-user@example.com", "192.168.1.2")
		s.Require().NoError(err)

		// Check for the existing identifier
		existingResult, err := s.service.Check(ctx, "existing-user@example.com", "192.168.1.2")
		s.NoError(err)

		// Both should be allowed (within limits)
		s.True(newResult.Allowed, "new identifier should be allowed")
		s.True(existingResult.Allowed, "existing identifier should be allowed")

		// Both should have the same limit
		s.Equal(newResult.Limit, existingResult.Limit, "limits should be identical")

		// The key security property: response structure should be consistent
		// so an attacker cannot infer account existence from response format
		s.Equal(s.config.AttemptsPerWindow, newResult.Limit)
		s.Equal(s.config.AttemptsPerWindow, existingResult.Limit)
	})

	s.Run("all code paths compute backoff for consistent timing", func() {
		// Even for accounts with zero failures, backoff should be computed
		// (returning 0) to maintain consistent code execution time
		result, err := s.service.Check(ctx, "timing-test-user@example.com", "192.168.1.100")
		s.NoError(err)

		// RetryAfter should be set (even if 0 for no backoff needed)
		s.GreaterOrEqual(result.RetryAfter, 0)
	})
}

// =============================================================================
// Constructor Tests (Invariant Enforcement)
// =============================================================================

func (s *AuthLockoutServiceSecuritySuite) TestNew() {
	s.Run("nil store returns error", func() {
		_, err := New(nil)
		s.Error(err)
		s.Contains(err.Error(), "auth lockout store is required")
	})

	s.Run("valid store returns configured service", func() {
		svc, err := New(s.store)
		s.NoError(err)
		s.NotNil(svc)
	})
}

// =============================================================================
// Progressive Backoff Tests
// =============================================================================

func (s *AuthLockoutServiceSecuritySuite) TestProgressiveBackoff() {
	s.Run("backoff increases with failure count", func() {
		backoff0 := s.service.GetProgressiveBackoff(0)
		backoff1 := s.service.GetProgressiveBackoff(1)
		backoff2 := s.service.GetProgressiveBackoff(2)
		backoff3 := s.service.GetProgressiveBackoff(3)

		s.Equal(time.Duration(0), backoff0, "zero failures should have no backoff")
		s.Equal(250*time.Millisecond, backoff1, "first failure: 250ms")
		s.Equal(500*time.Millisecond, backoff2, "second failure: 500ms")
		s.Equal(1*time.Second, backoff3, "third failure: 1s (capped)")
	})

	s.Run("backoff is capped at 1 second", func() {
		backoff10 := s.service.GetProgressiveBackoff(10)
		s.Equal(1*time.Second, backoff10, "high failure count should still cap at 1s")
	})
}

// =============================================================================
// Daily Failure Persistence Tests (Security)
// =============================================================================
// Security test: Verify DailyFailures resets after 24h even without successful login.

func (s *AuthLockoutServiceSecuritySuite) TestDailyFailurePersistence() {
	identifier := "daily-test-user"
	ip := "192.168.1.50"

	s.Run("daily failures accumulate across multiple failures", func() {
		ctx := context.Background()

		// Record multiple failures
		for i := 0; i < 3; i++ {
			_, err := s.service.RecordFailure(ctx, identifier, ip)
			s.NoError(err)
		}

		// Verify daily failures accumulated
		key := models.NewAuthLockoutKey(identifier, ip).String()
		record, err := s.store.Get(ctx, key)
		s.NoError(err)
		s.Equal(3, record.DailyFailures)
	})

	s.Run("daily failures persist within 24h window", func() {
		ctx := context.Background()
		identifier := "daily-persist-user"
		ip := "192.168.1.51"

		// Record failure 23 hours ago
		pastTime := time.Now().Add(-23 * time.Hour)
		ctx = requestcontext.WithTime(ctx, pastTime)

		_, err := s.service.RecordFailure(ctx, identifier, ip)
		s.NoError(err)

		// Run daily reset with cutoff at 24h ago (should NOT reset this user)
		cutoff := time.Now().Add(-24 * time.Hour)
		resetCount, err := s.store.ResetDailyFailures(context.Background(), cutoff)
		s.NoError(err)
		s.Equal(0, resetCount, "failures within 24h should not be reset")

		key := models.NewAuthLockoutKey(identifier, ip).String()
		record, _ := s.store.Get(context.Background(), key)
		s.Equal(1, record.DailyFailures, "daily failures should persist within 24h")
	})

	s.Run("daily failures reset after 24h without successful login", func() {
		ctx := context.Background()
		identifier := "daily-reset-user"
		ip := "192.168.1.52"

		// Record failure 25 hours ago
		pastTime := time.Now().Add(-25 * time.Hour)
		ctx = requestcontext.WithTime(ctx, pastTime)

		_, err := s.service.RecordFailure(ctx, identifier, ip)
		s.NoError(err)

		// Run daily reset with cutoff at 24h ago (should reset this user)
		cutoff := time.Now().Add(-24 * time.Hour)
		resetCount, err := s.store.ResetDailyFailures(context.Background(), cutoff)
		s.NoError(err)
		s.Equal(1, resetCount, "failures older than 24h should be reset")

		key := models.NewAuthLockoutKey(identifier, ip).String()
		record, _ := s.store.Get(context.Background(), key)
		s.Equal(0, record.DailyFailures, "daily failures should be reset after 24h")
	})
}

// =============================================================================
// Hard Lock Tests
// =============================================================================

func (s *AuthLockoutServiceSecuritySuite) TestHardLock() {
	ctx := context.Background()
	identifier := "hardlock-user"
	ip := "192.168.1.60"

	s.Run("hard lock triggers after threshold failures", func() {
		// Record failures up to hard lock threshold
		for i := 0; i < s.config.HardLockThreshold; i++ {
			_, err := s.service.RecordFailure(ctx, identifier, ip)
			s.NoError(err)
		}

		// Check should show locked
		result, err := s.service.Check(ctx, identifier, ip)
		s.NoError(err)
		s.False(result.Allowed, "should be locked after hard lock threshold")
		s.Greater(result.RetryAfter, 0, "should have retry after set")
	})
}

// =============================================================================
// Clear Failures Tests
// =============================================================================

func (s *AuthLockoutServiceSecuritySuite) TestClearFailures() {
	ctx := context.Background()
	identifier := "clear-test-user"
	ip := "192.168.1.70"

	s.Run("clear removes failure record", func() {
		// Record some failures
		_, err := s.service.RecordFailure(ctx, identifier, ip)
		s.NoError(err)

		// Clear failures
		err = s.service.Clear(ctx, identifier, ip)
		s.NoError(err)

		// Check should show clean state
		result, err := s.service.Check(ctx, identifier, ip)
		s.NoError(err)
		s.True(result.Allowed)
		s.Equal(s.config.AttemptsPerWindow, result.Remaining)
	})
}
