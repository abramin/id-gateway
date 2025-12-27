package tracer

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// OTelTracer wraps OpenTelemetry's tracer to satisfy our internal Tracer interface.
// This adapter allows the registry module to use OpenTelemetry without depending
// directly on its APIs throughout the codebase.
type OTelTracer struct {
	tracer trace.Tracer
}

// OTelOption configures the OTelTracer.
type OTelOption func(*OTelTracer)

// WithOTelTracer allows injecting a custom OpenTelemetry tracer.
// Useful for testing or when a pre-configured tracer is available.
func WithOTelTracer(t trace.Tracer) OTelOption {
	return func(o *OTelTracer) {
		o.tracer = t
	}
}

// NewOTel creates a new OpenTelemetry-backed tracer.
// By default, it uses the global tracer provider with "credo/registry" as the instrumentation name.
func NewOTel(opts ...OTelOption) *OTelTracer {
	t := &OTelTracer{}
	for _, opt := range opts {
		opt(t)
	}
	if t.tracer == nil {
		t.tracer = otel.Tracer("credo/registry")
	}
	return t
}

// Start creates a new span with the given name and attributes.
func (t *OTelTracer) Start(ctx context.Context, name string, attrs ...Attribute) (context.Context, Span) {
	otelAttrs := toOTelAttributes(attrs)
	ctx, span := t.tracer.Start(ctx, name, trace.WithAttributes(otelAttrs...))
	return ctx, &otelSpan{span: span}
}

// otelSpan wraps an OpenTelemetry span.
type otelSpan struct {
	span trace.Span
}

// End completes the span, recording any error.
func (s *otelSpan) End(err error) {
	if err != nil {
		s.span.RecordError(err)
		s.span.SetStatus(codes.Error, err.Error())
	}
	s.span.End()
}

// SetAttributes adds attributes to the span.
func (s *otelSpan) SetAttributes(attrs ...Attribute) {
	s.span.SetAttributes(toOTelAttributes(attrs)...)
}

// AddEvent records an event within the span.
func (s *otelSpan) AddEvent(name string, attrs ...Attribute) {
	s.span.AddEvent(name, trace.WithAttributes(toOTelAttributes(attrs)...))
}

// toOTelAttributes converts our Attribute type to OpenTelemetry attributes.
func toOTelAttributes(attrs []Attribute) []attribute.KeyValue {
	if len(attrs) == 0 {
		return nil
	}
	result := make([]attribute.KeyValue, 0, len(attrs))
	for _, a := range attrs {
		switch v := a.Value.(type) {
		case string:
			result = append(result, attribute.String(a.Key, v))
		case bool:
			result = append(result, attribute.Bool(a.Key, v))
		case int64:
			result = append(result, attribute.Int64(a.Key, v))
		case int:
			result = append(result, attribute.Int64(a.Key, int64(v)))
		case float64:
			result = append(result, attribute.Float64(a.Key, v))
		}
	}
	return result
}

// Verify interfaces are satisfied.
var (
	_ Tracer = (*OTelTracer)(nil)
	_ Span   = (*otelSpan)(nil)
)
