package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
)

// TestTenantDeactivate_AlreadyInactive verifies the domain invariant that
// deactivating an already-inactive tenant returns an error.
func TestTenantDeactivate_AlreadyInactive(t *testing.T) {
	tenant := &Tenant{
		ID:        id.TenantID(uuid.New()),
		Name:      "Test",
		Status:    TenantStatusInactive,
		CreatedAt: time.Now(),
	}

	err := tenant.Deactivate(time.Now())
	require.Error(t, err)
	assert.True(t, dErrors.HasCode(err, dErrors.CodeInvariantViolation),
		"expected invariant violation for double-deactivation")
}

// TestTenantDeactivate_Success verifies that deactivating an active tenant succeeds.
func TestTenantDeactivate_Success(t *testing.T) {
	now := time.Now()
	tenant := &Tenant{
		ID:        id.TenantID(uuid.New()),
		Name:      "Test",
		Status:    TenantStatusActive,
		CreatedAt: now,
	}

	err := tenant.Deactivate(now)
	require.NoError(t, err)
	assert.Equal(t, TenantStatusInactive, tenant.Status)
	assert.Equal(t, now, tenant.UpdatedAt)
}

// TestTenantReactivate_AlreadyActive verifies the domain invariant that
// reactivating an already-active tenant returns an error.
func TestTenantReactivate_AlreadyActive(t *testing.T) {
	tenant := &Tenant{
		ID:        id.TenantID(uuid.New()),
		Name:      "Test",
		Status:    TenantStatusActive,
		CreatedAt: time.Now(),
	}

	err := tenant.Reactivate(time.Now())
	require.Error(t, err)
	assert.True(t, dErrors.HasCode(err, dErrors.CodeInvariantViolation),
		"expected invariant violation for double-reactivation")
}

// TestTenantReactivate_Success verifies that reactivating an inactive tenant succeeds.
func TestTenantReactivate_Success(t *testing.T) {
	now := time.Now()
	tenant := &Tenant{
		ID:        id.TenantID(uuid.New()),
		Name:      "Test",
		Status:    TenantStatusInactive,
		CreatedAt: now,
	}

	err := tenant.Reactivate(now)
	require.NoError(t, err)
	assert.Equal(t, TenantStatusActive, tenant.Status)
	assert.Equal(t, now, tenant.UpdatedAt)
}

// TestClientDeactivate_AlreadyInactive verifies the domain invariant that
// deactivating an already-inactive client returns an error.
func TestClientDeactivate_AlreadyInactive(t *testing.T) {
	client := &Client{
		ID:            id.ClientID(uuid.New()),
		TenantID:      id.TenantID(uuid.New()),
		Name:          "Test Client",
		OAuthClientID: "test-client-id",
		Status:        ClientStatusInactive,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	err := client.Deactivate(time.Now())
	require.Error(t, err)
	assert.True(t, dErrors.HasCode(err, dErrors.CodeInvariantViolation),
		"expected invariant violation for double-deactivation")
}

// TestClientDeactivate_Success verifies that deactivating an active client succeeds.
func TestClientDeactivate_Success(t *testing.T) {
	now := time.Now()
	client := &Client{
		ID:            id.ClientID(uuid.New()),
		TenantID:      id.TenantID(uuid.New()),
		Name:          "Test Client",
		OAuthClientID: "test-client-id",
		Status:        ClientStatusActive,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	err := client.Deactivate(now)
	require.NoError(t, err)
	assert.Equal(t, ClientStatusInactive, client.Status)
	assert.Equal(t, now, client.UpdatedAt)
}

// TestClientReactivate_AlreadyActive verifies the domain invariant that
// reactivating an already-active client returns an error.
func TestClientReactivate_AlreadyActive(t *testing.T) {
	client := &Client{
		ID:            id.ClientID(uuid.New()),
		TenantID:      id.TenantID(uuid.New()),
		Name:          "Test Client",
		OAuthClientID: "test-client-id",
		Status:        ClientStatusActive,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	err := client.Reactivate(time.Now())
	require.Error(t, err)
	assert.True(t, dErrors.HasCode(err, dErrors.CodeInvariantViolation),
		"expected invariant violation for double-reactivation")
}

// TestClientReactivate_Success verifies that reactivating an inactive client succeeds.
func TestClientReactivate_Success(t *testing.T) {
	now := time.Now()
	client := &Client{
		ID:            id.ClientID(uuid.New()),
		TenantID:      id.TenantID(uuid.New()),
		Name:          "Test Client",
		OAuthClientID: "test-client-id",
		Status:        ClientStatusInactive,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	err := client.Reactivate(now)
	require.NoError(t, err)
	assert.Equal(t, ClientStatusActive, client.Status)
	assert.Equal(t, now, client.UpdatedAt)
}

// TestTenantIsActive verifies the IsActive helper method.
func TestTenantIsActive(t *testing.T) {
	active := &Tenant{Status: TenantStatusActive}
	inactive := &Tenant{Status: TenantStatusInactive}

	assert.True(t, active.IsActive())
	assert.False(t, inactive.IsActive())
}

// TestClientIsActive verifies the IsActive helper method.
func TestClientIsActive(t *testing.T) {
	active := &Client{Status: ClientStatusActive}
	inactive := &Client{Status: ClientStatusInactive}

	assert.True(t, active.IsActive())
	assert.False(t, inactive.IsActive())
}

// TestClientIsConfidential verifies the IsConfidential helper method.
func TestClientIsConfidential(t *testing.T) {
	confidential := &Client{ClientSecretHash: "hashed-secret"}
	public := &Client{ClientSecretHash: ""}

	assert.True(t, confidential.IsConfidential())
	assert.False(t, public.IsConfidential())
}
