package tracer

import "context"

// NoopTracer is a tracer that does nothing.
// Use this in tests to avoid tracing overhead and external dependencies.
type NoopTracer struct{}

// NewNoop creates a new no-op tracer.
func NewNoop() *NoopTracer {
	return &NoopTracer{}
}

// Start returns the context unchanged and a no-op span.
func (t *NoopTracer) Start(ctx context.Context, _ string, _ ...Attribute) (context.Context, Span) {
	return ctx, &noopSpan{}
}

// noopSpan is a span that does nothing.
type noopSpan struct{}

func (s *noopSpan) End(_ error)                  {}
func (s *noopSpan) SetAttributes(_ ...Attribute) {}
func (s *noopSpan) AddEvent(_ string, _ ...Attribute) {}

// Verify interfaces are satisfied.
var (
	_ Tracer = (*NoopTracer)(nil)
	_ Span   = (*noopSpan)(nil)
)
