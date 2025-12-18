package tenant

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"credo/internal/sentinel"
	"credo/internal/tenant/models"
)

func TestCreateIfNameAvailable_Success(t *testing.T) {
	store := NewInMemory()
	ctx := context.Background()

	tenant := &models.Tenant{
		ID:        uuid.New(),
		Name:      "Test Tenant",
		Status:    "active",
		CreatedAt: time.Now(),
	}

	err := store.CreateIfNameAvailable(ctx, tenant)
	require.NoError(t, err)

	found, err := store.FindByID(ctx, tenant.ID)
	require.NoError(t, err)
	assert.Equal(t, tenant.Name, found.Name)
}

func TestCreateIfNameAvailable_DuplicateNameReturnsError(t *testing.T) {
	store := NewInMemory()
	ctx := context.Background()

	tenant1 := &models.Tenant{
		ID:        uuid.New(),
		Name:      "Duplicate",
		Status:    "active",
		CreatedAt: time.Now(),
	}
	tenant2 := &models.Tenant{
		ID:        uuid.New(),
		Name:      "Duplicate",
		Status:    "active",
		CreatedAt: time.Now(),
	}

	require.NoError(t, store.CreateIfNameAvailable(ctx, tenant1))

	err := store.CreateIfNameAvailable(ctx, tenant2)
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel.ErrAlreadyUsed)
}

func TestCreateIfNameAvailable_CaseInsensitive(t *testing.T) {
	store := NewInMemory()
	ctx := context.Background()

	tenant1 := &models.Tenant{
		ID:        uuid.New(),
		Name:      "MyTenant",
		Status:    "active",
		CreatedAt: time.Now(),
	}
	tenant2 := &models.Tenant{
		ID:        uuid.New(),
		Name:      "MYTENANT",
		Status:    "active",
		CreatedAt: time.Now(),
	}

	require.NoError(t, store.CreateIfNameAvailable(ctx, tenant1))

	err := store.CreateIfNameAvailable(ctx, tenant2)
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel.ErrAlreadyUsed)
}

func TestFindByID_NotFound(t *testing.T) {
	store := NewInMemory()
	ctx := context.Background()

	_, err := store.FindByID(ctx, uuid.New())
	require.ErrorIs(t, err, ErrNotFound)
}

func TestFindByName_CaseInsensitive(t *testing.T) {
	store := NewInMemory()
	ctx := context.Background()

	tenant := &models.Tenant{
		ID:        uuid.New(),
		Name:      "CaseSensitive",
		Status:    "active",
		CreatedAt: time.Now(),
	}
	require.NoError(t, store.CreateIfNameAvailable(ctx, tenant))

	// Find with different case
	found, err := store.FindByName(ctx, "casesensitive")
	require.NoError(t, err)
	assert.Equal(t, tenant.ID, found.ID)

	found, err = store.FindByName(ctx, "CASESENSITIVE")
	require.NoError(t, err)
	assert.Equal(t, tenant.ID, found.ID)
}
