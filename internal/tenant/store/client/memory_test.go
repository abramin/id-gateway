package client

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"credo/internal/tenant/models"
)

func TestCreate_IndexesByClientID(t *testing.T) {
	store := NewInMemory()
	ctx := context.Background()

	client := &models.Client{
		ID:        uuid.New(),
		TenantID:  uuid.New(),
		Name:      "Test Client",
		ClientID:  "test-client-id",
		Status:    "active",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	require.NoError(t, store.Create(ctx, client))

	// Should be findable by ClientID
	found, err := store.FindByClientID(ctx, "test-client-id")
	require.NoError(t, err)
	assert.Equal(t, client.ID, found.ID)
}

func TestFindByTenantAndID_WrongTenant(t *testing.T) {
	store := NewInMemory()
	ctx := context.Background()

	tenantA := uuid.New()
	tenantB := uuid.New()

	client := &models.Client{
		ID:        uuid.New(),
		TenantID:  tenantA,
		Name:      "Client A",
		ClientID:  "client-a",
		Status:    "active",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	require.NoError(t, store.Create(ctx, client))

	// Should find with correct tenant
	found, err := store.FindByTenantAndID(ctx, tenantA, client.ID)
	require.NoError(t, err)
	assert.Equal(t, client.ID, found.ID)

	// Should NOT find with wrong tenant
	_, err = store.FindByTenantAndID(ctx, tenantB, client.ID)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestFindByID_NotFound(t *testing.T) {
	store := NewInMemory()
	ctx := context.Background()

	_, err := store.FindByID(ctx, uuid.New())
	require.ErrorIs(t, err, ErrNotFound)
}

func TestFindByClientID_NotFound(t *testing.T) {
	store := NewInMemory()
	ctx := context.Background()

	_, err := store.FindByClientID(ctx, "nonexistent")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestCountByTenant_OnlyCountsMatchingTenant(t *testing.T) {
	store := NewInMemory()
	ctx := context.Background()

	tenantA := uuid.New()
	tenantB := uuid.New()

	// Create 2 clients for tenant A
	for i := 0; i < 2; i++ {
		client := &models.Client{
			ID:        uuid.New(),
			TenantID:  tenantA,
			Name:      "Client A",
			ClientID:  uuid.NewString(),
			Status:    "active",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		require.NoError(t, store.Create(ctx, client))
	}

	// Create 3 clients for tenant B
	for i := 0; i < 3; i++ {
		client := &models.Client{
			ID:        uuid.New(),
			TenantID:  tenantB,
			Name:      "Client B",
			ClientID:  uuid.NewString(),
			Status:    "active",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		require.NoError(t, store.Create(ctx, client))
	}

	countA, err := store.CountByTenant(ctx, tenantA)
	require.NoError(t, err)
	assert.Equal(t, 2, countA)

	countB, err := store.CountByTenant(ctx, tenantB)
	require.NoError(t, err)
	assert.Equal(t, 3, countB)
}
