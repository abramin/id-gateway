// Package tracer provides a lightweight tracing abstraction for the registry module.
//
// This package defines an internal tracer interface that doesn't depend directly on
// OpenTelemetry APIs, allowing the registry module to emit distributed traces while
// remaining decoupled from specific tracing implementations.
//
// The interface supports:
//   - Starting parent and child spans with attributes
//   - Recording errors on span completion
//   - Adding span events for audit trail correlation
//   - Cache hit/miss annotations
//
// Implementations:
//   - NoopTracer: For tests (zero overhead)
//   - OTelTracer: OpenTelemetry adapter for production
package tracer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Span represents an active trace span.
// Spans track the execution of a single operation and can record errors and events.
type Span interface {
	// End completes the span, recording any error that occurred.
	// If err is non-nil, the span is marked as failed.
	// End must be called exactly once, typically via defer.
	End(err error)

	// SetAttributes adds key-value pairs to the span.
	// Attributes provide context for debugging and analysis.
	SetAttributes(attrs ...Attribute)

	// AddEvent records a timestamped event within the span.
	// Events mark significant points during span execution.
	AddEvent(name string, attrs ...Attribute)
}

// Tracer creates spans for distributed tracing.
// Implementations must be safe for concurrent use.
type Tracer interface {
	// Start creates a new span with the given name and attributes.
	// The returned context contains the new span and should be passed to child operations.
	// The span must be ended by calling Span.End().
	//
	// Example:
	//   ctx, span := tracer.Start(ctx, "registry.check",
	//       tracer.String("national_id", hashedID),
	//       tracer.Bool("regulated_mode", true),
	//   )
	//   defer span.End(nil)
	Start(ctx context.Context, name string, attrs ...Attribute) (context.Context, Span)
}

// Attribute represents a key-value pair attached to spans.
type Attribute struct {
	Key   string
	Value any
}

// String creates a string attribute.
func String(key, value string) Attribute {
	return Attribute{Key: key, Value: value}
}

// Bool creates a boolean attribute.
func Bool(key string, value bool) Attribute {
	return Attribute{Key: key, Value: value}
}

// Int64 creates an int64 attribute.
func Int64(key string, value int64) Attribute {
	return Attribute{Key: key, Value: value}
}

// Float64 creates a float64 attribute.
func Float64(key string, value float64) Attribute {
	return Attribute{Key: key, Value: value}
}

// Duration creates a duration attribute in milliseconds.
func Duration(key string, value time.Duration) Attribute {
	return Attribute{Key: key, Value: value.Milliseconds()}
}

// HashNationalID returns a SHA-256 hash of the national ID for safe logging in traces.
// This allows correlation of traces without exposing PII.
func HashNationalID(nationalID string) string {
	if nationalID == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(nationalID))
	return hex.EncodeToString(hash[:8]) // First 8 bytes for brevity
}

// Span names used by the registry module.
const (
	SpanRegistryCheck    = "registry.check"
	SpanRegistryCitizen  = "registry.citizen"
	SpanRegistrySanction = "registry.sanctions"
	SpanCitizenCall      = "registry.citizen.call"
	SpanSanctionsCall    = "registry.sanctions.call"
)

// Attribute keys used by the registry module.
const (
	AttrNationalID       = "national_id"
	AttrRegulatedMode    = "regulated_mode"
	AttrCacheHit         = "cache.hit"
	AttrCacheTTLRemainMs = "cache.ttl_remaining_ms"
	AttrSimulatedLatency = "simulated_latency_ms"
	AttrTestDataBranch   = "test_data_branch"
	AttrListed           = "listed"
	AttrAgeBucket        = "age_bucket"
)

// Event names used by the registry module.
const (
	EventAuditEmitted = "audit.emitted"
)
