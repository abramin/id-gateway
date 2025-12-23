package quota

import (
	"context"
	"credo/internal/ratelimit/config"
	"credo/pkg/domain"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemoryQuotaStore(t *testing.T) {
	store := New(config.DefaultConfig())
	ctx := context.Background()

	res, err := store.GetQuota(ctx, domain.APIKeyID("missing"))
	require.NoError(t, err)
	assert.Nil(t, res)
	// Verify existing quota is returned without mutating usage or period boundaries
	res, err = store.IncrementUsage(ctx, domain.APIKeyID("existing"), 5)
	require.NoError(t, err)
	assert.NotNil(t, res)

	got, err := store.GetQuota(ctx, domain.APIKeyID("existing"))
	require.NoError(t, err)
	assert.Equal(t, res, got)

	// Verify GetQuota doesn't mutate the quota
	usageBefore := got.CurrentUsage
	periodStartBefore := got.PeriodStart
	periodEndBefore := got.PeriodEnd

	got2, err := store.GetQuota(ctx, domain.APIKeyID("existing"))
	require.NoError(t, err)
	assert.Equal(t, usageBefore, got2.CurrentUsage, "GetQuota should not mutate usage")
	assert.Equal(t, periodStartBefore, got2.PeriodStart, "GetQuota should not mutate period start")
	assert.Equal(t, periodEndBefore, got2.PeriodEnd, "GetQuota should not mutate period end")
}
