package tracer_test

import (
	"context"
	"errors"
	"testing"

	"credo/internal/evidence/registry/tracer"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoopTracer_Start(t *testing.T) {
	tr := tracer.NewNoop()
	ctx := context.Background()

	newCtx, span := tr.Start(ctx, "test.span",
		tracer.String("key", "value"),
		tracer.Bool("flag", true),
	)

	// Context should be returned unchanged
	assert.Equal(t, ctx, newCtx)
	// Span should not be nil
	require.NotNil(t, span)

	// Span methods should not panic
	span.SetAttributes(tracer.String("another", "attr"))
	span.AddEvent("test.event", tracer.Int64("count", 42))
	span.End(nil)
}

func TestNoopTracer_SpanEndWithError(t *testing.T) {
	tr := tracer.NewNoop()
	ctx := context.Background()

	_, span := tr.Start(ctx, "test.span")
	require.NotNil(t, span)

	// Should not panic when ending with error
	span.End(errors.New("test error"))
}

func TestHashNationalID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantLen  int
		wantSame bool
	}{
		{
			name:    "empty string returns empty",
			input:   "",
			wantLen: 0,
		},
		{
			name:    "short ID produces 16 char hash",
			input:   "123",
			wantLen: 16,
		},
		{
			name:    "long ID produces 16 char hash",
			input:   "123456789012345",
			wantLen: 16,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tracer.HashNationalID(tt.input)
			assert.Len(t, result, tt.wantLen)
		})
	}
}

func TestHashNationalID_Deterministic(t *testing.T) {
	id := "123456789"
	hash1 := tracer.HashNationalID(id)
	hash2 := tracer.HashNationalID(id)
	assert.Equal(t, hash1, hash2, "same input should produce same hash")
}

func TestHashNationalID_DifferentInputs(t *testing.T) {
	hash1 := tracer.HashNationalID("123456789")
	hash2 := tracer.HashNationalID("987654321")
	assert.NotEqual(t, hash1, hash2, "different inputs should produce different hashes")
}

func TestAttributeConstructors(t *testing.T) {
	t.Run("String", func(t *testing.T) {
		attr := tracer.String("key", "value")
		assert.Equal(t, "key", attr.Key)
		assert.Equal(t, "value", attr.Value)
	})

	t.Run("Bool", func(t *testing.T) {
		attr := tracer.Bool("flag", true)
		assert.Equal(t, "flag", attr.Key)
		assert.Equal(t, true, attr.Value)
	})

	t.Run("Int64", func(t *testing.T) {
		attr := tracer.Int64("count", 42)
		assert.Equal(t, "count", attr.Key)
		assert.Equal(t, int64(42), attr.Value)
	})

	t.Run("Float64", func(t *testing.T) {
		attr := tracer.Float64("ratio", 3.14)
		assert.Equal(t, "ratio", attr.Key)
		assert.Equal(t, 3.14, attr.Value)
	})

	t.Run("Duration", func(t *testing.T) {
		attr := tracer.Duration("latency", 150*1e6) // 150ms in nanoseconds
		assert.Equal(t, "latency", attr.Key)
		assert.Equal(t, int64(150), attr.Value)
	})
}

func TestSpanConstants(t *testing.T) {
	// Verify span names match PRD-003 requirements
	assert.Equal(t, "registry.check", tracer.SpanRegistryCheck)
	assert.Equal(t, "registry.citizen", tracer.SpanRegistryCitizen)
	assert.Equal(t, "registry.sanctions", tracer.SpanRegistrySanction)
	assert.Equal(t, "registry.citizen.call", tracer.SpanCitizenCall)
	assert.Equal(t, "registry.sanctions.call", tracer.SpanSanctionsCall)
}

func TestAttributeConstants(t *testing.T) {
	// Verify attribute keys match PRD-003 requirements
	assert.Equal(t, "national_id", tracer.AttrNationalID)
	assert.Equal(t, "regulated_mode", tracer.AttrRegulatedMode)
	assert.Equal(t, "cache.hit", tracer.AttrCacheHit)
	assert.Equal(t, "cache.ttl_remaining_ms", tracer.AttrCacheTTLRemainMs)
}

func TestEventConstants(t *testing.T) {
	// Verify event names match PRD-003 requirements
	assert.Equal(t, "audit.emitted", tracer.EventAuditEmitted)
}
