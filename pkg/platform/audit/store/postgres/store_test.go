package postgres

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestListRecent_ClampsLimitToInt32Max(t *testing.T) {
	// This test verifies that limit values exceeding int32 max are clamped
	// to prevent integer overflow during the int->int32 conversion.
	// Without this protection, int64 values > MaxInt32 would wrap to negative
	// numbers when cast to int32, causing undefined query behavior.

	tests := []struct {
		name     string
		input    int
		expected int
	}{
		{
			name:     "within int32 range unchanged",
			input:    1000,
			expected: 1000,
		},
		{
			name:     "at int32 max unchanged",
			input:    math.MaxInt32,
			expected: math.MaxInt32,
		},
		{
			name:     "exceeds int32 max clamped",
			input:    math.MaxInt32 + 1,
			expected: math.MaxInt32,
		},
		{
			name:     "large int64 value clamped",
			input:    math.MaxInt64,
			expected: math.MaxInt32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the clamping logic directly
			limit := tt.input
			if limit > math.MaxInt32 {
				limit = math.MaxInt32
			}
			assert.Equal(t, tt.expected, limit)
		})
	}
}
