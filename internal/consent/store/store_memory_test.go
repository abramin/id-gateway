package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"id-gateway/internal/consent/models"
)

func TestInMemoryStoreOperations(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()
	now := time.Now()
	expiry := now.Add(time.Hour)

	// Save and find
	record := &models.ConsentRecord{ID: "consent_1", UserID: "user1", Purpose: models.ConsentPurposeLogin, GrantedAt: now, ExpiresAt: &expiry}
	require.NoError(t, store.Save(ctx, record))

	fetched, err := store.FindByUserAndPurpose(ctx, "user1", models.ConsentPurposeLogin)
	require.NoError(t, err)
	assert.Equal(t, record.ID, fetched.ID)

	// Update
	newExpiry := now.Add(2 * time.Hour)
	record.ExpiresAt = &newExpiry
	require.NoError(t, store.Update(ctx, record))
	fetched, err = store.FindByUserAndPurpose(ctx, "user1", models.ConsentPurposeLogin)
	require.NoError(t, err)
	require.NotNil(t, fetched.ExpiresAt)
	assert.Equal(t, newExpiry, *fetched.ExpiresAt)

	// Revoke
	revokeTime := now.Add(30 * time.Minute)
	require.NoError(t, store.RevokeByUserAndPurpose(ctx, "user1", models.ConsentPurposeLogin, revokeTime))
	fetched, err = store.FindByUserAndPurpose(ctx, "user1", models.ConsentPurposeLogin)
	require.NoError(t, err)
	require.NotNil(t, fetched.RevokedAt)
	assert.Equal(t, revokeTime, *fetched.RevokedAt)

	// List copy integrity
	list, err := store.ListByUser(ctx, "user1")
	require.NoError(t, err)
	require.Len(t, list, 1)
	list[0].UserID = "mutated"
	fetchedAgain, err := store.FindByUserAndPurpose(ctx, "user1", models.ConsentPurposeLogin)
	require.NoError(t, err)
	assert.Equal(t, "user1", fetchedAgain.UserID)

	// Delete
	require.NoError(t, store.DeleteByUser(ctx, "user1"))
	fetched, err = store.FindByUserAndPurpose(ctx, "user1", models.ConsentPurposeLogin)
	require.NoError(t, err)
	assert.Nil(t, fetched)
}
