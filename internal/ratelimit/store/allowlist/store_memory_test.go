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

// TestInMemoryAllowlistStore_Add tests adding entries to the allowlist.
// Per PRD-017 FR-4: Allowlist management.
func TestInMemoryAllowlistStore_Add(t *testing.T) {
	store := NewInMemoryAllowlistStore()
	ctx := context.Background()

	testCases := []struct {
		name  string
		entry *models.AllowlistEntry
	}{
		{
			name:  "add IP entry",
			entry: newAllowlistEntry(t, models.AllowlistTypeIP, "192.168.1.100"),
		},
		{
			name:  "add user_id entry",
			entry: newAllowlistEntry(t, models.AllowlistTypeUserID, uuid.NewString()),
		},
		{
			name: "add entry with expiration",
			entry: newAllowlistEntry(
				t,
				models.AllowlistTypeUserID,
				uuid.NewString(),
				withExpiry(time.Now().Add(time.Hour)),
			),
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := store.Add(ctx, tc.entry)
			require.NoError(t, err)
		})
	}
}

func TestInMemoryAllowlistStore_Remove(t *testing.T) {
	store := NewInMemoryAllowlistStore()
	ctx := context.Background()
	entry := newAllowlistEntry(t, models.AllowlistTypeIP, "transient-ip")

	t.Run("remove existing entry", func(t *testing.T) {
		err := store.Add(ctx, entry)
		require.NoError(t, err)
		err = store.Remove(ctx, entry.Type, entry.Identifier)
		require.NoError(t, err)

		// Verify it's removed
		allowed, err := store.IsAllowlisted(ctx, entry.Identifier)
		require.NoError(t, err)
		assert.False(t, allowed)
	})

	t.Run("remove non-existent entry", func(t *testing.T) {
		err := store.Remove(ctx, models.AllowlistTypeIP, "non-existent-ip")
		require.NoError(t, err)
	})
}

// Per PRD-017 FR-4: Middleware check before rate limiting.
func TestInMemoryAllowlistStore_IsAllowlisted(t *testing.T) {
	ctx := context.Background()
	activeEntry := newAllowlistEntry(t, models.AllowlistTypeIP, "transient-ip")
	expiredEntry := newAllowlistEntry(t, models.AllowlistTypeIP, "expired-ip", withExpiry(time.Now().Add(-1*time.Hour)))

	testCases := []struct {
		name       string
		identifier string
		setup      func(t *testing.T, store *InMemoryAllowlistStore)
		expected   bool
	}{
		{
			name:       "non-existent identifier returns false",
			identifier: "unknown-ip",
			setup: func(t *testing.T, store *InMemoryAllowlistStore) {
				t.Helper()
			},
			expected: false,
		},
		{
			name:       "existing IP entry returns true",
			identifier: activeEntry.Identifier,
			setup: func(t *testing.T, store *InMemoryAllowlistStore) {
				t.Helper()
				err := store.Add(ctx, activeEntry)
				require.NoError(t, err)
			},
			expected: true,
		},
		{
			name:       "expired entry returns false",
			identifier: expiredEntry.Identifier,
			setup: func(t *testing.T, store *InMemoryAllowlistStore) {
				t.Helper()
				err := store.Add(ctx, expiredEntry)
				require.NoError(t, err)
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			store := NewInMemoryAllowlistStore()
			if tc.setup != nil {
				tc.setup(t, store)
			}
			allowed, err := store.IsAllowlisted(ctx, tc.identifier)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, allowed)
		})
	}
}

func TestInMemoryAllowlistStore_List(t *testing.T) {
	ctx := context.Background()

	store := NewInMemoryAllowlistStore()

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
	store := NewInMemoryAllowlistStore()
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
