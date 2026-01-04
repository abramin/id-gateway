// Package ops provides a fire-and-forget audit publisher for operational events.
//
// OpsTracker emits operational events with optional sampling and circuit breaker.
// Events are fire-and-forget with no retry. Sampling reduces volume for
// high-frequency events. A circuit breaker prevents thundering herd on
// audit store outages.
//
// Use for: session_created, token_*, userinfo_accessed, tenant_created, etc.
package ops

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	audit "credo/pkg/platform/audit"
)

// Publisher emits operational events with fire-and-forget semantics.
type Publisher struct {
	store          audit.Store
	sampler        *Sampler
	circuitBreaker *CircuitBreaker
	logger         *slog.Logger
	metrics        *Metrics

	// Stats
	tracked               int64
	sampled               int64
	circuitBreakerDropped int64
	persistFailures       int64
}

// Option configures the Publisher.
type Option func(*Publisher)

// WithLogger sets a logger for error reporting.
func WithLogger(logger *slog.Logger) Option {
	return func(p *Publisher) {
		p.logger = logger
	}
}

// WithMetrics sets the metrics collector.
func WithMetrics(m *Metrics) Option {
	return func(p *Publisher) {
		p.metrics = m
	}
}

// WithSampleRate sets the default sample rate (0.0-1.0).
func WithSampleRate(rate float64) Option {
	return func(p *Publisher) {
		p.sampler = NewSampler(rate)
	}
}

// WithCircuitThreshold sets the failure count to open the circuit.
func WithCircuitThreshold(threshold int) Option {
	return func(p *Publisher) {
		p.circuitBreaker = NewCircuitBreaker(threshold, time.Minute)
	}
}

// WithCircuitCooldown sets the circuit breaker cooldown duration.
func WithCircuitCooldown(d time.Duration) Option {
	return func(p *Publisher) {
		if p.circuitBreaker != nil {
			p.circuitBreaker = NewCircuitBreaker(p.circuitBreaker.threshold, d)
		} else {
			p.circuitBreaker = NewCircuitBreaker(5, d)
		}
	}
}

// New creates an ops publisher with sampling and circuit breaker.
func New(store audit.Store, opts ...Option) *Publisher {
	p := &Publisher{
		store:          store,
		sampler:        NewSampler(0.1), // default 10% sample rate
		circuitBreaker: NewCircuitBreaker(5, time.Minute),
	}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

// Track emits an operational event with sampling.
// This is fire-and-forget - never blocks, no guarantees.
// Events may be sampled based on configuration.
func (p *Publisher) Track(event audit.OpsEvent) {
	// Sampling check
	if !p.sampler.ShouldSample(event.Action) {
		atomic.AddInt64(&p.sampled, 1)
		if p.metrics != nil {
			p.metrics.IncSampled()
		}
		return
	}

	p.trackInternal(event)
}

func (p *Publisher) trackInternal(event audit.OpsEvent) {
	// Circuit breaker check
	if !p.circuitBreaker.Allow() {
		atomic.AddInt64(&p.circuitBreakerDropped, 1)
		if p.metrics != nil {
			p.metrics.IncCircuitBreakerDropped()
			p.metrics.SetCircuitBreakerState(true)
		}
		return
	}

	// Set timestamp if not provided
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Fire-and-forget persistence in goroutine
	go p.persist(context.Background(), event)
}

func (p *Publisher) persist(ctx context.Context, event audit.OpsEvent) {
	// Convert to legacy Event for store compatibility
	legacyEvent := event.ToLegacyEvent()

	if err := p.store.Append(ctx, legacyEvent); err != nil {
		p.circuitBreaker.RecordFailure()
		atomic.AddInt64(&p.persistFailures, 1)
		if p.metrics != nil {
			p.metrics.IncPersistFailures()
			p.metrics.SetCircuitBreakerState(p.circuitBreaker.IsOpen())
		}
		// No retry - fire and forget
		return
	}

	p.circuitBreaker.RecordSuccess()
	atomic.AddInt64(&p.tracked, 1)
	if p.metrics != nil {
		p.metrics.IncTracked()
		p.metrics.SetCircuitBreakerState(false)
	}
}

// Close is a no-op for the ops publisher (no buffering).
func (p *Publisher) Close() error {
	return nil
}

// SetSampleRate sets the sample rate for a specific action.
func (p *Publisher) SetSampleRate(action string, rate float64) {
	p.sampler.SetRate(action, rate)
}

// Stats returns tracking statistics for monitoring.
func (p *Publisher) Stats() Stats {
	return Stats{
		Tracked:               atomic.LoadInt64(&p.tracked),
		Sampled:               atomic.LoadInt64(&p.sampled),
		CircuitBreakerDropped: atomic.LoadInt64(&p.circuitBreakerDropped),
		PersistFailures:       atomic.LoadInt64(&p.persistFailures),
		CircuitOpen:           p.circuitBreaker.IsOpen(),
	}
}

// Stats holds tracking statistics.
type Stats struct {
	Tracked               int64 // Events successfully tracked
	Sampled               int64 // Events dropped due to sampling
	CircuitBreakerDropped int64 // Events dropped due to circuit breaker
	PersistFailures       int64 // Persistence failures (counted in circuit breaker)
	CircuitOpen           bool  // Current circuit breaker state
}
