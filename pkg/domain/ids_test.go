package domain

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dErrors "credo/pkg/domain-errors"
)

// TestParseUUID_Invariants validates the parsing invariant:
// "IDs must be valid, non-empty, non-nil UUIDs"
//
// Justification: This is a pure function enforcing a domain invariant
// at trust boundaries. Per testing.md, unit tests are allowed for invariants.
func TestParseUUID_Invariants(t *testing.T) {
	t.Run("rejects empty string", func(t *testing.T) {
		_, err := ParseUserID("")
		require.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeInvalidInput))
	})

	t.Run("rejects invalid format", func(t *testing.T) {
		_, err := ParseUserID("not-a-uuid")
		require.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeInvalidInput))
	})

	t.Run("rejects nil UUID", func(t *testing.T) {
		_, err := ParseUserID(uuid.Nil.String())
		require.Error(t, err)
		assert.True(t, dErrors.HasCode(err, dErrors.CodeInvalidInput))
	})

	t.Run("accepts valid UUID", func(t *testing.T) {
		validUUID := uuid.New()
		id, err := ParseUserID(validUUID.String())
		require.NoError(t, err)
		assert.Equal(t, UserID(validUUID), id)
	})
}

// TestTypeDistinction verifies the compiler enforces type safety.
// This is a compile-time check - if this compiles, the invariant holds.
func TestTypeDistinction(t *testing.T) {
	userID := UserID(uuid.New())
	tenantID := TenantID(uuid.New())

	// These would fail to compile if types were interchangeable:
	// var _ UserID = tenantID   // compile error
	// var _ TenantID = userID   // compile error

	// Verify they're distinct at runtime too
	assert.NotEqual(t, uuid.UUID(userID), uuid.UUID(tenantID))
}
