package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"credo/internal/ratelimit/models"
)

// MockBucketStore is a test double for BucketStore.
type MockBucketStore struct {
	AllowFunc           func(ctx context.Context, key string, limit int, window time.Duration) (*models.RateLimitResult, error)
	AllowNFunc          func(ctx context.Context, key string, cost int, limit int, window time.Duration) (*models.RateLimitResult, error)
	ResetFunc           func(ctx context.Context, key string) error
	GetCurrentCountFunc func(ctx context.Context, key string) (int, error)
}

func (m *MockBucketStore) Allow(ctx context.Context, key string, limit int, window time.Duration) (*models.RateLimitResult, error) {
	if m.AllowFunc != nil {
		return m.AllowFunc(ctx, key, limit, window)
	}
	return &models.RateLimitResult{Allowed: true, Limit: limit, Remaining: limit - 1, ResetAt: time.Now().Add(window)}, nil
}

func (m *MockBucketStore) AllowN(ctx context.Context, key string, cost int, limit int, window time.Duration) (*models.RateLimitResult, error) {
	if m.AllowNFunc != nil {
		return m.AllowNFunc(ctx, key, cost, limit, window)
	}
	return &models.RateLimitResult{Allowed: true, Limit: limit, Remaining: limit - cost, ResetAt: time.Now().Add(window)}, nil
}

func (m *MockBucketStore) Reset(ctx context.Context, key string) error {
	if m.ResetFunc != nil {
		return m.ResetFunc(ctx, key)
	}
	return nil
}

func (m *MockBucketStore) GetCurrentCount(ctx context.Context, key string) (int, error) {
	if m.GetCurrentCountFunc != nil {
		return m.GetCurrentCountFunc(ctx, key)
	}
	return 0, nil
}

// MockAllowlistStore is a test double for AllowlistStore.
type MockAllowlistStore struct {
	AddFunc           func(ctx context.Context, entry *models.AllowlistEntry) error
	RemoveFunc        func(ctx context.Context, entryType models.AllowlistEntryType, identifier string) error
	IsAllowlistedFunc func(ctx context.Context, identifier string) (bool, error)
	ListFunc          func(ctx context.Context) ([]*models.AllowlistEntry, error)
}

func (m *MockAllowlistStore) Add(ctx context.Context, entry *models.AllowlistEntry) error {
	if m.AddFunc != nil {
		return m.AddFunc(ctx, entry)
	}
	return nil
}

func (m *MockAllowlistStore) Remove(ctx context.Context, entryType models.AllowlistEntryType, identifier string) error {
	if m.RemoveFunc != nil {
		return m.RemoveFunc(ctx, entryType, identifier)
	}
	return nil
}

func (m *MockAllowlistStore) IsAllowlisted(ctx context.Context, identifier string) (bool, error) {
	if m.IsAllowlistedFunc != nil {
		return m.IsAllowlistedFunc(ctx, identifier)
	}
	return false, nil
}

func (m *MockAllowlistStore) List(ctx context.Context) ([]*models.AllowlistEntry, error) {
	if m.ListFunc != nil {
		return m.ListFunc(ctx)
	}
	return nil, nil
}

// TestService_CheckIPRateLimit tests per-IP rate limiting.
// Per PRD-017 FR-1: Per-IP rate limiting.
func TestService_CheckIPRateLimit(t *testing.T) {
	t.Skip("TODO: Implement test after CheckIPRateLimit is implemented")

	buckets := &MockBucketStore{}
	allowlist := &MockAllowlistStore{}
	svc, err := New(buckets, allowlist)
	require.NoError(t, err)

	ctx := context.Background()

	// TODO: Test cases to implement:
	// 1. Request allowed when under limit
	// 2. Request denied when at/over limit
	// 3. Allowlisted IP bypasses limits
	// 4. Correct endpoint class limits applied

	t.Run("request allowed under limit", func(t *testing.T) {
		buckets.AllowFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*models.RateLimitResult, error) {
			return &models.RateLimitResult{Allowed: true, Limit: 10, Remaining: 9}, nil
		}

		result, err := svc.CheckIPRateLimit(ctx, "192.168.1.1", models.ClassAuth)
		require.NoError(t, err)
		assert.True(t, result.Allowed)
		assert.Equal(t, 9, result.Remaining)
	})

	t.Run("request denied at limit", func(t *testing.T) {
		// TODO: Implement
	})

	t.Run("allowlisted IP bypasses limit", func(t *testing.T) {
		// TODO: Implement
	})
}

// TestService_CheckUserRateLimit tests per-user rate limiting.
// Per PRD-017 FR-2: Per-user rate limiting.
func TestService_CheckUserRateLimit(t *testing.T) {
	t.Skip("TODO: Implement test after CheckUserRateLimit is implemented")

	buckets := &MockBucketStore{}
	allowlist := &MockAllowlistStore{}
	svc, err := New(buckets, allowlist)
	require.NoError(t, err)

	ctx := context.Background()

	// TODO: Test cases to implement:
	// 1. User request allowed under limit
	// 2. User request denied at limit
	// 3. Different limits for different endpoint classes

	t.Run("user request allowed under limit", func(t *testing.T) {
		// TODO: Implement
		_ = svc
		_ = ctx
	})
}

// TestService_CheckBothLimits tests combined IP and user rate limiting.
// Per PRD-017 FR-2: Both must pass for authenticated endpoints.
func TestService_CheckBothLimits(t *testing.T) {
	t.Skip("TODO: Implement test after CheckBothLimits is implemented")

	buckets := &MockBucketStore{}
	allowlist := &MockAllowlistStore{}
	svc, err := New(buckets, allowlist)
	require.NoError(t, err)

	ctx := context.Background()

	// TODO: Test cases to implement:
	// 1. Both limits pass → allowed
	// 2. IP limit fails, user limit passes → denied
	// 3. IP limit passes, user limit fails → denied
	// 4. Both limits fail → denied

	t.Run("both limits pass", func(t *testing.T) {
		// TODO: Implement
		_ = svc
		_ = ctx
	})

	t.Run("IP limit fails user limit passes", func(t *testing.T) {
		// TODO: Implement
	})
}

// TestService_CheckAuthRateLimit tests auth-specific rate limiting with lockout.
// Per PRD-017 FR-2b: OWASP authentication protections.
func TestService_CheckAuthRateLimit(t *testing.T) {
	t.Skip("TODO: Implement test after CheckAuthRateLimit is implemented")

	buckets := &MockBucketStore{}
	allowlist := &MockAllowlistStore{}
	svc, err := New(buckets, allowlist)
	require.NoError(t, err)

	ctx := context.Background()

	// TODO: Test cases to implement:
	// 1. Request allowed when not locked
	// 2. Request denied when locked
	// 3. Composite key includes email and IP

	t.Run("request allowed when not locked", func(t *testing.T) {
		// TODO: Implement
		_ = svc
		_ = ctx
	})
}

// TestService_RecordAuthFailure tests auth failure recording.
// Per PRD-017 FR-2b: Track failures for lockout.
func TestService_RecordAuthFailure(t *testing.T) {
	t.Skip("TODO: Implement test after RecordAuthFailure is implemented")

	buckets := &MockBucketStore{}
	allowlist := &MockAllowlistStore{}
	svc, err := New(buckets, allowlist)
	require.NoError(t, err)

	ctx := context.Background()

	// TODO: Test cases to implement:
	// 1. Failure count incremented
	// 2. Lockout triggered at threshold
	// 3. Hard lock after daily threshold

	t.Run("failure count incremented", func(t *testing.T) {
		// TODO: Implement
		_ = svc
		_ = ctx
	})
}

// TestService_GetProgressiveBackoff tests backoff calculation.
// Per PRD-017 FR-2b: Progressive backoff (250ms → 500ms → 1s).
func TestService_GetProgressiveBackoff(t *testing.T) {
	t.Skip("TODO: Implement test after GetProgressiveBackoff is implemented")

	buckets := &MockBucketStore{}
	allowlist := &MockAllowlistStore{}
	svc, err := New(buckets, allowlist)
	require.NoError(t, err)

	// TODO: Test cases to implement:
	// 1. First failure: 250ms
	// 2. Second failure: 500ms
	// 3. Third+ failure: 1s (capped)

	t.Run("progressive backoff values", func(t *testing.T) {
		delay1 := svc.GetProgressiveBackoff(1)
		assert.Equal(t, 250*time.Millisecond, delay1)

		delay2 := svc.GetProgressiveBackoff(2)
		assert.Equal(t, 500*time.Millisecond, delay2)

		delay3 := svc.GetProgressiveBackoff(3)
		assert.Equal(t, time.Second, delay3)
	})
}

// TestService_AddToAllowlist tests allowlist addition.
// Per PRD-017 FR-4: Admin allowlist management.
func TestService_AddToAllowlist(t *testing.T) {
	t.Skip("TODO: Implement test after AddToAllowlist is implemented")

	buckets := &MockBucketStore{}
	allowlist := &MockAllowlistStore{}
	svc, err := New(buckets, allowlist)
	require.NoError(t, err)

	ctx := context.Background()

	// TODO: Test cases to implement:
	// 1. IP added successfully
	// 2. User ID added successfully
	// 3. Entry with expiration

	t.Run("add IP to allowlist", func(t *testing.T) {
		// TODO: Implement
		_ = svc
		_ = ctx
	})
}

// TestService_ResetRateLimit tests admin reset operation.
// Per PRD-017 TR-1: Admin reset operation.
func TestService_ResetRateLimit(t *testing.T) {
	t.Skip("TODO: Implement test after ResetRateLimit is implemented")

	buckets := &MockBucketStore{}
	allowlist := &MockAllowlistStore{}
	svc, err := New(buckets, allowlist)
	require.NoError(t, err)

	ctx := context.Background()

	// TODO: Test cases to implement:
	// 1. Reset clears rate limit for identifier
	// 2. Reset specific class only
	// 3. Reset all classes for identifier

	t.Run("reset clears rate limit", func(t *testing.T) {
		// TODO: Implement
		_ = svc
		_ = ctx
	})
}

// TestConfig_Defaults tests default configuration.
func TestConfig_Defaults(t *testing.T) {
	cfg := DefaultConfig()

	// Per PRD-017 FR-1: IP rate limits
	authLimit, authWindow := cfg.GetIPLimit(models.ClassAuth)
	assert.Equal(t, 10, authLimit)
	assert.Equal(t, time.Minute, authWindow)

	sensitiveLimit, _ := cfg.GetIPLimit(models.ClassSensitive)
	assert.Equal(t, 30, sensitiveLimit)

	readLimit, _ := cfg.GetIPLimit(models.ClassRead)
	assert.Equal(t, 100, readLimit)

	// Per PRD-017 FR-6: Global limits
	assert.Equal(t, 1000, cfg.Global.PerInstancePerSecond)
	assert.Equal(t, 10000, cfg.Global.GlobalPerSecond)
}
