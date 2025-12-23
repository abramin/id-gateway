package globalthrottle

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemoryGlobalThrottleStore(t *testing.T) {
	store := New()
	ctx := context.Background()

	current, err := store.GetGlobalCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, current)

	current, blocked, err := store.IncrementGlobal(ctx)
	require.NoError(t, err)
	assert.False(t, blocked)
	assert.Equal(t, 1, current)

	for range 10 {
		_, _, _ = store.IncrementGlobal(ctx)
	}

	current, err = store.GetGlobalCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 11, current)
}
