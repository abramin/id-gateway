package allowlist

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"credo/internal/ratelimit/models"
	id "credo/pkg/domain"
)

// NOTE: Basic Add/Remove tests for IP entries are covered by E2E FR-4 scenarios.
// Only user_id paths and edge cases not covered by E2E are tested here.
func TestInMemoryAllowlistStore_Add(t *testing.T) {
	store := New()
	ctx := context.Background()

	// user_id path not covered by E2E (E2E only tests IP allowlisting)
	t.Run("add user_id entry", func(t *testing.T) {
		entry := newAllowlistEntry(t, models.AllowlistTypeUserID, uuid.NewString())
		err := store.Add(ctx, entry)
		require.NoError(t, err)
	})
}

func TestInMemoryAllowlistStore_Remove(t *testing.T) {
	store := New()
	ctx := context.Background()

	// Idempotency edge case: remove non-existent entry should succeed (not covered by E2E)
	t.Run("remove non-existent entry is idempotent", func(t *testing.T) {
		err := store.Remove(ctx, models.AllowlistTypeIP, "non-existent-ip")
		require.NoError(t, err)
	})
}

// NOTE: IsAllowlisted tests (non-existent, existing, expired) are covered by
// E2E FR-4 scenarios: "Allowlisted IP bypasses limits", "Allowlist entry expires"

func TestInMemoryAllowlistStore_List(t *testing.T) {
	ctx := context.Background()

	store := New()

	t.Run("empty store returns empty list", func(t *testing.T) {
		entries, err := store.List(ctx)
		require.NoError(t, err)
		assert.Empty(t, entries)
	})

	t.Run("returns non-expired entries", func(t *testing.T) {
		active := newAllowlistEntry(t, models.AllowlistTypeIP, "active-ip")
		activeUser := newAllowlistEntry(t, models.AllowlistTypeUserID, "active-user", withExpiry(time.Now().Add(time.Hour)))
		expired := newAllowlistEntry(t, models.AllowlistTypeIP, "expired-ip", withExpiry(time.Now().Add(-time.Hour)))

		err := store.Add(ctx, active)
		require.NoError(t, err)
		err = store.Add(ctx, activeUser)
		require.NoError(t, err)
		err = store.Add(ctx, expired)
		require.NoError(t, err)

		entries, err := store.List(ctx)
		require.NoError(t, err)
		assert.Len(t, entries, 2)
		for _, e := range entries {
			assert.NotEqual(t, expired.Identifier, e.Identifier)
		}
	})
}

func TestInMemoryAllowlistStore_Concurrent(t *testing.T) {
	store := New()
	ctx := context.Background()

	numGoroutines := 50
	done := make(chan struct{})

	// Concurrently add entries
	for i := range numGoroutines {
		go func(i int) {
			entry := newAllowlistEntry(t, models.AllowlistTypeIP, "concurrent-ip-"+strconv.Itoa(i))
			err := store.Add(ctx, entry)
			require.NoError(t, err)
			done <- struct{}{}
		}(i)
	}

	// Wait for all adds to complete
	for range make([]struct{}, numGoroutines) {
		<-done
	}
	// Verify all entries were added
	entries, err := store.List(ctx)
	require.NoError(t, err)
	assert.Len(t, entries, numGoroutines)
}

func newAllowlistEntry(t *testing.T, entryType models.AllowlistEntryType, identifier string, opts ...func(*models.AllowlistEntry)) *models.AllowlistEntry {
	t.Helper()
	entry := &models.AllowlistEntry{
		ID:         identifier,
		Type:       entryType,
		Identifier: identifier,
		Reason:     "test",
		CreatedAt:  time.Now(),
		CreatedBy:  id.UserID(uuid.New()),
	}
	for _, opt := range opts {
		opt(entry)
	}
	return entry
}

func withExpiry(at time.Time) func(*models.AllowlistEntry) {
	return func(entry *models.AllowlistEntry) {
		entry.ExpiresAt = &at
	}
}
