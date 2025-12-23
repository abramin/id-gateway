package checker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"credo/internal/ratelimit/config"
	"credo/internal/ratelimit/models"
	"credo/internal/ratelimit/service/authlockout"
	"credo/internal/ratelimit/service/globalthrottle"
	"credo/internal/ratelimit/service/quota"
	"credo/internal/ratelimit/service/requestlimit"
	rwallowlistStore "credo/internal/ratelimit/store/allowlist"
	authlockoutStore "credo/internal/ratelimit/store/authlockout"
	rwbucketStore "credo/internal/ratelimit/store/bucket"
	globalthrottleStore "credo/internal/ratelimit/store/globalthrottle"
	quotaStore "credo/internal/ratelimit/store/quota"
	id "credo/pkg/domain"
)

// =============================================================================
// Checker Facade Test Suite
// =============================================================================
// Justification: The checker facade orchestrates the 4 rate limiting services.
// These tests verify constructor invariants and the CheckAuthRateLimit
// orchestration logic (auth lockout + IP rate limit as secondary defense).

type CheckerFacadeSuite struct {
	suite.Suite
	requestSvc       *requestlimit.Service
	authLockoutSvc   *authlockout.Service
	quotaSvc         *quota.Service
	globalThrottleSvc *globalthrottle.Service
	service          *Service
}

func TestCheckerFacadeSuite(t *testing.T) {
	suite.Run(t, new(CheckerFacadeSuite))
}

func (s *CheckerFacadeSuite) SetupTest() {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create real services with in-memory stores
	var err error
	s.requestSvc, err = requestlimit.New(
		rwbucketStore.New(),
		rwallowlistStore.New(),
		requestlimit.WithLogger(logger),
		requestlimit.WithConfig(cfg),
	)
	s.Require().NoError(err)

	s.authLockoutSvc, err = authlockout.New(
		authlockoutStore.New(),
		authlockout.WithLogger(logger),
		authlockout.WithConfig(&cfg.AuthLockout),
	)
	s.Require().NoError(err)

	s.quotaSvc, err = quota.New(
		quotaStore.New(cfg),
		quota.WithLogger(logger),
	)
	s.Require().NoError(err)

	s.globalThrottleSvc, err = globalthrottle.New(
		globalthrottleStore.New(),
		globalthrottle.WithLogger(logger),
		globalthrottle.WithConfig(&cfg.Global),
	)
	s.Require().NoError(err)

	s.service, err = New(
		s.requestSvc,
		s.authLockoutSvc,
		s.quotaSvc,
		s.globalThrottleSvc,
		WithLogger(logger),
	)
	s.Require().NoError(err)
}

// =============================================================================
// Constructor Tests (Invariant Enforcement)
// =============================================================================

func (s *CheckerFacadeSuite) TestNew() {
	s.Run("nil requests service returns error", func() {
		_, err := New(nil, s.authLockoutSvc, s.quotaSvc, s.globalThrottleSvc)
		s.Error(err)
		s.Contains(err.Error(), "requests service is required")
	})

	s.Run("nil auth lockout service returns error", func() {
		_, err := New(s.requestSvc, nil, s.quotaSvc, s.globalThrottleSvc)
		s.Error(err)
		s.Contains(err.Error(), "auth lockout service is required")
	})

	s.Run("nil quota service returns error", func() {
		_, err := New(s.requestSvc, s.authLockoutSvc, nil, s.globalThrottleSvc)
		s.Error(err)
		s.Contains(err.Error(), "quotas service is required")
	})

	s.Run("nil global throttle service returns error", func() {
		_, err := New(s.requestSvc, s.authLockoutSvc, s.quotaSvc, nil)
		s.Error(err)
		s.Contains(err.Error(), "global throttle service is required")
	})

	s.Run("valid services returns configured facade", func() {
		svc, err := New(s.requestSvc, s.authLockoutSvc, s.quotaSvc, s.globalThrottleSvc)
		s.NoError(err)
		s.NotNil(svc)
	})
}

// =============================================================================
// Delegation Tests
// =============================================================================
// Justification: Verify that facade methods correctly delegate to services.

func (s *CheckerFacadeSuite) TestDelegation() {
	ctx := context.Background()

	s.Run("CheckIPRateLimit delegates to requestlimit service", func() {
		result, err := s.service.CheckIPRateLimit(ctx, "192.168.1.1", models.ClassRead)
		s.NoError(err)
		s.NotNil(result)
		s.True(result.Allowed)
	})

	s.Run("CheckUserRateLimit delegates to requestlimit service", func() {
		result, err := s.service.CheckUserRateLimit(ctx, "user-123", models.ClassRead)
		s.NoError(err)
		s.NotNil(result)
		s.True(result.Allowed)
	})

	s.Run("CheckBothLimits delegates to requestlimit service", func() {
		result, err := s.service.CheckBothLimits(ctx, "192.168.1.1", "user-123", models.ClassRead)
		s.NoError(err)
		s.NotNil(result)
		s.True(result.Allowed)
	})

	s.Run("CheckGlobalThrottle delegates to globalthrottle service", func() {
		// Returns allowed=true when not blocked (semantics changed from blocked to allowed)
		allowed, err := s.service.CheckGlobalThrottle(ctx)
		s.NoError(err)
		s.True(allowed)
	})

	s.Run("GetProgressiveBackoff delegates to authlockout service", func() {
		delay := s.service.GetProgressiveBackoff(1)
		s.Equal(250*time.Millisecond, delay)
	})
}

// =============================================================================
// CheckAuthRateLimit Orchestration Tests
// =============================================================================
// Justification: CheckAuthRateLimit has orchestration logic that combines
// auth lockout check with IP rate limiting as secondary defense.

func (s *CheckerFacadeSuite) TestCheckAuthRateLimitOrchestration() {
	ctx := context.Background()

	s.Run("passes when auth lockout allows and IP rate limit allows", func() {
		result, err := s.service.CheckAuthRateLimit(ctx, "user@example.com", "192.168.1.1")
		s.NoError(err)
		s.NotNil(result)
		s.True(result.Allowed)
	})

	s.Run("blocked when auth lockout is locked", func() {
		// Record enough failures to trigger lockout
		for i := 0; i < 10; i++ {
			_, _ = s.service.RecordAuthFailure(ctx, "locked@example.com", "192.168.1.2")
		}

		result, err := s.service.CheckAuthRateLimit(ctx, "locked@example.com", "192.168.1.2")
		s.NoError(err)
		s.NotNil(result)
		s.False(result.Allowed)
	})
}

// =============================================================================
// CheckAPIKeyQuota Tests
// =============================================================================

func (s *CheckerFacadeSuite) TestCheckAPIKeyQuota() {
	ctx := context.Background()

	s.Run("returns not found for unknown API key", func() {
		_, err := s.service.CheckAPIKeyQuota(ctx, id.APIKeyID("unknown-key"))
		s.Error(err)
		s.Contains(err.Error(), "quota not found")
	})
}

// =============================================================================
// Error Propagation from Services
// =============================================================================
// Justification: Verify that errors from underlying services are propagated.

type errorRequestService struct{}

func (e *errorRequestService) CheckIP(ctx context.Context, ip string, class models.EndpointClass) (*models.RateLimitResult, error) {
	return nil, errors.New("request service error")
}
func (e *errorRequestService) CheckUser(ctx context.Context, userID string, class models.EndpointClass) (*models.RateLimitResult, error) {
	return nil, errors.New("request service error")
}
func (e *errorRequestService) CheckBoth(ctx context.Context, ip, userID string, class models.EndpointClass) (*models.RateLimitResult, error) {
	return nil, errors.New("request service error")
}

// Note: Cannot easily test error propagation without mocking the services.
// The focused service tests cover error propagation from stores.
