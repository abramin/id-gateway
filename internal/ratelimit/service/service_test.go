package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"credo/internal/ratelimit/models"
)

// TestConfig_Defaults tests default configuration.
// Pure function test - validates config values match PRD-017 requirements.
func TestConfig_Defaults(t *testing.T) {
	cfg := DefaultConfig()

	authLimit, authWindow := cfg.GetIPLimit(models.ClassAuth)
	assert.Equal(t, 10, authLimit)
	assert.Equal(t, time.Minute, authWindow)

	sensitiveLimit, _ := cfg.GetIPLimit(models.ClassSensitive)
	assert.Equal(t, 30, sensitiveLimit)

	readLimit, _ := cfg.GetIPLimit(models.ClassRead)
	assert.Equal(t, 100, readLimit)

	assert.Equal(t, 1000, cfg.Global.PerInstancePerSecond)
	assert.Equal(t, 10000, cfg.Global.GlobalPerSecond)
}

// TestService_GetProgressiveBackoff tests backoff calculation.
// Pure function test - validates backoff values per PRD-017 FR-2b (250ms → 500ms → 1s).
func TestService_GetProgressiveBackoff(t *testing.T) {
	buckets := &noopBucketStore{}
	allowlist := &noopAllowlistStore{}
	svc, err := New(buckets, allowlist)
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	t.Run("first failure returns 250ms", func(t *testing.T) {
		delay := svc.GetProgressiveBackoff(1)
		assert.Equal(t, 250*time.Millisecond, delay)
	})

	t.Run("second failure returns 500ms", func(t *testing.T) {
		delay := svc.GetProgressiveBackoff(2)
		assert.Equal(t, 500*time.Millisecond, delay)
	})

	t.Run("third failure returns 1s (capped)", func(t *testing.T) {
		delay := svc.GetProgressiveBackoff(3)
		assert.Equal(t, time.Second, delay)
	})

	t.Run("fourth failure still returns 1s (capped)", func(t *testing.T) {
		delay := svc.GetProgressiveBackoff(4)
		assert.Equal(t, time.Second, delay)
	})

	t.Run("zero failures returns 0", func(t *testing.T) {
		delay := svc.GetProgressiveBackoff(0)
		assert.Equal(t, time.Duration(0), delay)
	})
}

// noopBucketStore is a minimal implementation for testing pure functions.
// Not used for behavior testing - only to satisfy constructor requirements.
type noopBucketStore struct{}

func (n *noopBucketStore) Allow(_ context.Context, _ string, limit int, window time.Duration) (*models.RateLimitResult, error) {
	return &models.RateLimitResult{Allowed: true, Limit: limit, Remaining: limit - 1, ResetAt: time.Now().Add(window)}, nil
}

func (n *noopBucketStore) AllowN(_ context.Context, _ string, cost, limit int, window time.Duration) (*models.RateLimitResult, error) {
	return &models.RateLimitResult{Allowed: true, Limit: limit, Remaining: limit - cost, ResetAt: time.Now().Add(window)}, nil
}

func (n *noopBucketStore) Reset(_ context.Context, _ string) error {
	return nil
}

func (n *noopBucketStore) GetCurrentCount(_ context.Context, _ string) (int, error) {
	return 0, nil
}

// noopAllowlistStore is a minimal implementation for testing pure functions.
type noopAllowlistStore struct{}

func (n *noopAllowlistStore) Add(_ context.Context, _ *models.AllowlistEntry) error {
	return nil
}

func (n *noopAllowlistStore) Remove(_ context.Context, _ models.AllowlistEntryType, _ string) error {
	return nil
}

func (n *noopAllowlistStore) IsAllowlisted(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func (n *noopAllowlistStore) List(_ context.Context) ([]*models.AllowlistEntry, error) {
	return nil, nil
}
