package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Unit tests for APIVersion domain primitive.
// Justification: Pure domain logic with edge cases in parsing and comparison.

func TestParseAPIVersion(t *testing.T) {
	t.Run("parses valid v1", func(t *testing.T) {
		v, err := ParseAPIVersion("v1")
		require.NoError(t, err)
		assert.Equal(t, APIVersionV1, v)
	})

	t.Run("rejects unknown version", func(t *testing.T) {
		_, err := ParseAPIVersion("v99")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown API version")
	})

	t.Run("rejects empty string", func(t *testing.T) {
		_, err := ParseAPIVersion("")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown API version")
	})

	t.Run("rejects malformed versions", func(t *testing.T) {
		cases := []string{"1", "V1", "version1", "v1.0", " v1", "v1 "}
		for _, c := range cases {
			_, err := ParseAPIVersion(c)
			require.Error(t, err, "expected error for %q", c)
		}
	})
}

func TestAPIVersion_String(t *testing.T) {
	assert.Equal(t, "v1", APIVersionV1.String())
	assert.Equal(t, "", APIVersion("").String())
}

func TestAPIVersion_IsNil(t *testing.T) {
	t.Run("empty is nil", func(t *testing.T) {
		assert.True(t, APIVersion("").IsNil())
	})

	t.Run("v1 is not nil", func(t *testing.T) {
		assert.False(t, APIVersionV1.IsNil())
	})
}

func TestAPIVersion_IsAtLeast(t *testing.T) {
	// These tests document the forward compatibility contract:
	// - v1 token on v2 route: routeVersion(v2).IsAtLeast(tokenVersion(v1)) = true (OK)
	// - v2 token on v1 route: routeVersion(v1).IsAtLeast(tokenVersion(v2)) = false (REJECTED)

	t.Run("v1 >= v1 (same version)", func(t *testing.T) {
		assert.True(t, APIVersionV1.IsAtLeast(APIVersionV1))
	})

	t.Run("known version >= empty (known beats empty)", func(t *testing.T) {
		assert.True(t, APIVersionV1.IsAtLeast(APIVersion("")))
	})

	t.Run("known version >= unknown (known beats unknown)", func(t *testing.T) {
		assert.True(t, APIVersionV1.IsAtLeast(APIVersion("v99")))
	})

	t.Run("empty >= v1 is false (empty loses)", func(t *testing.T) {
		assert.False(t, APIVersion("").IsAtLeast(APIVersionV1))
	})

	t.Run("unknown >= v1 is false (unknown loses)", func(t *testing.T) {
		assert.False(t, APIVersion("v99").IsAtLeast(APIVersionV1))
	})

	t.Run("empty >= empty is false (both unknown)", func(t *testing.T) {
		assert.False(t, APIVersion("").IsAtLeast(APIVersion("")))
	})
}

func TestSupportedVersions(t *testing.T) {
	versions := SupportedVersions()
	require.Len(t, versions, 1)
	assert.Equal(t, APIVersionV1, versions[0])
}

func TestDefaultVersion(t *testing.T) {
	assert.Equal(t, APIVersionV1, DefaultVersion())
}
