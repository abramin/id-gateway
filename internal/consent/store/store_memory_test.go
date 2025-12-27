package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"credo/internal/consent/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"
)

func TestInMemoryStoreOperations(t *testing.T) {
	store := New()
	ctx := context.Background()
	now := time.Now()
	expiry := now.Add(time.Hour)

	// Save and find
	record := &models.Record{ID: id.ConsentID(uuid.New()), UserID: id.UserID(uuid.New()), Purpose: models.PurposeLogin, GrantedAt: now, ExpiresAt: &expiry}
	require.NoError(t, store.Save(ctx, record))

	fetched, err := store.FindByUserAndPurpose(ctx, record.UserID, models.PurposeLogin)
	require.NoError(t, err)
	assert.Equal(t, record.ID, fetched.ID)

	// Update
	newExpiry := now.Add(2 * time.Hour)
	record.ExpiresAt = &newExpiry
	require.NoError(t, store.Update(ctx, record))
	fetched, err = store.FindByUserAndPurpose(ctx, record.UserID, models.PurposeLogin)
	require.NoError(t, err)
	require.NotNil(t, fetched.ExpiresAt)
	assert.Equal(t, newExpiry, *fetched.ExpiresAt)

	// Revoke
	revokeTime := now.Add(30 * time.Minute)
	res, err := store.RevokeByUserAndPurpose(ctx, record.UserID, models.PurposeLogin, revokeTime)
	require.NoError(t, err)
	assert.Equal(t, record.ID, res.ID)
	require.NotNil(t, res.RevokedAt)
	assert.Equal(t, revokeTime, *res.RevokedAt)

	// List copy integrity
	list, err := store.ListByUser(ctx, record.UserID, nil)
	require.NoError(t, err)
	require.Len(t, list, 1)
	list[0].UserID = id.UserID(uuid.New()) // Modify the fetched copy
	fetched, err = store.FindByUserAndPurpose(ctx, record.UserID, models.PurposeLogin)
	require.NoError(t, err)
	assert.Equal(t, record.UserID, fetched.UserID) // Original should remain unchanged

	// Find non-existing
	noRecord, err := store.FindByUserAndPurpose(ctx, id.UserID(uuid.New()), models.PurposeLogin)
	require.ErrorIs(t, err, sentinel.ErrNotFound)
	assert.Nil(t, noRecord)

	// Delete
	require.NoError(t, store.DeleteByUser(ctx, record.UserID))
	fetched, err = store.FindByUserAndPurpose(ctx, record.UserID, models.PurposeLogin)
	require.ErrorIs(t, err, sentinel.ErrNotFound)
	assert.Nil(t, fetched)
}
