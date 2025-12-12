package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"credo/internal/consent/models"
)

func TestInMemoryStoreOperations(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()
	now := time.Now()
	expiry := now.Add(time.Hour)

	// Save and find
	record := &models.Record{ID: "consent_1", UserID: "user1", Purpose: models.PurposeLogin, GrantedAt: now, ExpiresAt: &expiry}
	require.NoError(t, store.Save(ctx, record))

	fetched, err := store.FindByUserAndPurpose(ctx, "user1", models.PurposeLogin)
	require.NoError(t, err)
	assert.Equal(t, record.ID, fetched.ID)

	// Update
	newExpiry := now.Add(2 * time.Hour)
	record.ExpiresAt = &newExpiry
	require.NoError(t, store.Update(ctx, record))
	fetched, err = store.FindByUserAndPurpose(ctx, "user1", models.PurposeLogin)
	require.NoError(t, err)
	require.NotNil(t, fetched.ExpiresAt)
	assert.Equal(t, newExpiry, *fetched.ExpiresAt)

	// Revoke
	revokeTime := now.Add(30 * time.Minute)
	res, err := store.RevokeByUserAndPurpose(ctx, "user1", models.PurposeLogin, revokeTime)
	require.NoError(t, err)
	assert.Equal(t, record.ID, res.ID)
	require.NotNil(t, res.RevokedAt)
	assert.Equal(t, revokeTime, *res.RevokedAt)

	// List copy integrity
	list, err := store.ListByUser(ctx, "user1", nil)
	require.NoError(t, err)
	require.Len(t, list, 1)
	list[0].UserID = "mutated"
	fetchedAgain, err := store.FindByUserAndPurpose(ctx, "user1", models.PurposeLogin)
	require.NoError(t, err)
	assert.Equal(t, "user1", fetchedAgain.UserID)

	// Delete
	require.NoError(t, store.DeleteByUser(ctx, "user1"))
	fetched, err = store.FindByUserAndPurpose(ctx, "user1", models.PurposeLogin)
	require.ErrorIs(t, err, ErrNotFound)
	assert.Nil(t, fetched)
}
