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
// This is a unit test because the invariant protects against invalid state transitions
// that may not be reachable via feature tests (no deactivate endpoint exists yet).
func TestTenantDeactivate_AlreadyInactive(t *testing.T) {
	tenant := &Tenant{
		ID:        id.TenantID(uuid.New()),
		Name:      "Test",
		Status:    TenantStatusInactive,
		CreatedAt: time.Now(),
	}

	err := tenant.Deactivate()
	require.Error(t, err)
	assert.True(t, dErrors.HasCode(err, dErrors.CodeInvariantViolation),
		"expected invariant violation for double-deactivation")
}

// TestTenantDeactivate_Success verifies that deactivating an active tenant succeeds.
func TestTenantDeactivate_Success(t *testing.T) {
	tenant := &Tenant{
		ID:        id.TenantID(uuid.New()),
		Name:      "Test",
		Status:    TenantStatusActive,
		CreatedAt: time.Now(),
	}

	err := tenant.Deactivate()
	require.NoError(t, err)
	assert.Equal(t, TenantStatusInactive, tenant.Status)
}

// TestClientDeactivate_AlreadyInactive verifies the domain invariant that
// deactivating an already-inactive client returns an error.
// This is a unit test because the invariant protects against invalid state transitions
// that may not be reachable via feature tests (no deactivate endpoint exists yet).
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

	err := client.Deactivate()
	require.Error(t, err)
	assert.True(t, dErrors.HasCode(err, dErrors.CodeInvariantViolation),
		"expected invariant violation for double-deactivation")
}

// TestClientDeactivate_Success verifies that deactivating an active client succeeds.
func TestClientDeactivate_Success(t *testing.T) {
	client := &Client{
		ID:            id.ClientID(uuid.New()),
		TenantID:      id.TenantID(uuid.New()),
		Name:          "Test Client",
		OAuthClientID: "test-client-id",
		Status:        ClientStatusActive,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	err := client.Deactivate()
	require.NoError(t, err)
	assert.Equal(t, ClientStatusInactive, client.Status)
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
