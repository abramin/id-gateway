// Package security provides an async-buffered audit publisher for security events.
//
// SecurityAuditor emits security events asynchronously with buffering and retry.
// Events are buffered in-memory and flushed to the store in batches.
// The caller never blocks on audit writes. Failed events are retried with
// exponential backoff. If the buffer is full, oldest events are dropped.
//
// Use for: auth_failed, session_revoked, rate_limit_exceeded, lockouts, etc.
package security

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	audit "credo/pkg/platform/audit"
)

// Publisher emits security events asynchronously with buffering and retry.
type Publisher struct {
	store   audit.Store
	buffer  *RingBuffer
	logger  *slog.Logger
	metrics *Metrics

	// Retry configuration
	maxRetries   int
	retryBackoff time.Duration

	// Flush configuration
	flushInterval time.Duration
	batchSize     int

	// Background worker
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Stats
	flushed           int64
	retries           int64
	droppedAfterRetry int64
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

// WithBufferSize sets the buffer capacity.
func WithBufferSize(size int) Option {
	return func(p *Publisher) {
		p.buffer = NewRingBuffer(size)
	}
}

// WithMaxRetries sets the maximum retry attempts.
func WithMaxRetries(n int) Option {
	return func(p *Publisher) {
		p.maxRetries = n
	}
}

// WithRetryBackoff sets the base retry backoff duration.
func WithRetryBackoff(d time.Duration) Option {
	return func(p *Publisher) {
		p.retryBackoff = d
	}
}

// WithFlushInterval sets the flush interval.
func WithFlushInterval(d time.Duration) Option {
	return func(p *Publisher) {
		p.flushInterval = d
	}
}

// WithBatchSize sets the batch size for flushing.
func WithBatchSize(n int) Option {
	return func(p *Publisher) {
		p.batchSize = n
	}
}

// New creates a security publisher with background flushing.
func New(store audit.Store, opts ...Option) *Publisher {
	p := &Publisher{
		store:         store,
		buffer:        NewRingBuffer(10000), // default 10K
		maxRetries:    3,
		retryBackoff:  100 * time.Millisecond,
		flushInterval: 50 * time.Millisecond,
		batchSize:     100,
	}
	p.ctx, p.cancel = context.WithCancel(context.Background())

	for _, opt := range opts {
		opt(p)
	}

	// Start background flusher
	p.wg.Add(1)
	go p.flushLoop()

	return p
}

// Emit queues a security event for async persistence.
// This method never blocks and does not return errors.
// Fire-and-forget from the caller's perspective.
func (p *Publisher) Emit(ctx context.Context, event audit.SecurityEvent) {
	// Set timestamp if not provided
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Non-blocking enqueue with drop-oldest semantics
	p.buffer.Enqueue(event)

	if p.metrics != nil {
		p.metrics.SetQueueDepth(int64(p.buffer.Len()))
	}
}

// Flush forces immediate flush of buffered events.
// Used during graceful shutdown.
func (p *Publisher) Flush(ctx context.Context) error {
	return p.flushBatch(ctx)
}

// Close drains the buffer and shuts down the publisher.
func (p *Publisher) Close() error {
	p.cancel()
	p.wg.Wait()

	// Final drain
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for p.buffer.Len() > 0 {
		if err := p.flushBatch(ctx); err != nil {
			if p.logger != nil {
				p.logger.Warn("failed to drain security audit buffer on shutdown", "error", err)
			}
			break
		}
	}

	return nil
}

// Stats returns buffer statistics for monitoring.
func (p *Publisher) Stats() BufferStats {
	return BufferStats{
		Queued:            int64(p.buffer.Len()),
		Flushed:           atomic.LoadInt64(&p.flushed),
		Dropped:           p.buffer.Dropped(),
		DroppedAfterRetry: atomic.LoadInt64(&p.droppedAfterRetry),
		Retries:           atomic.LoadInt64(&p.retries),
	}
}

// BufferStats holds buffer statistics.
type BufferStats struct {
	Queued            int64 // Events currently in buffer
	Flushed           int64 // Events successfully flushed
	Dropped           int64 // Events dropped due to buffer overflow
	DroppedAfterRetry int64 // Events dropped after exhausting retries
	Retries           int64 // Total retry attempts
}

func (p *Publisher) flushLoop() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			_ = p.flushBatch(p.ctx) //nolint:errcheck // periodic flush; errors logged internally
		}
	}
}

func (p *Publisher) flushBatch(ctx context.Context) error {
	events := p.buffer.DequeueBatch(p.batchSize)
	if len(events) == 0 {
		return nil
	}

	for _, event := range events {
		p.persistWithRetry(ctx, event)
	}

	if p.metrics != nil {
		p.metrics.SetQueueDepth(int64(p.buffer.Len()))
	}

	return nil
}

func (p *Publisher) persistWithRetry(ctx context.Context, event audit.SecurityEvent) {
	// Convert to legacy Event for store compatibility
	legacyEvent := event.ToLegacyEvent()

	var lastErr error
	for attempt := 0; attempt <= p.maxRetries; attempt++ {
		if err := p.store.Append(ctx, legacyEvent); err != nil {
			lastErr = err
			atomic.AddInt64(&p.retries, 1)
			if p.metrics != nil {
				p.metrics.IncRetries()
			}

			// Exponential backoff
			backoff := p.retryBackoff * time.Duration(1<<attempt)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			continue
		}

		// Success
		atomic.AddInt64(&p.flushed, 1)
		if p.metrics != nil {
			p.metrics.IncFlushed()
		}
		return
	}

	// All retries exhausted - log and drop
	atomic.AddInt64(&p.droppedAfterRetry, 1)
	if p.metrics != nil {
		p.metrics.IncDroppedAfterRetry()
	}
	if p.logger != nil {
		p.logger.WarnContext(ctx, "security audit dropped after retries",
			"action", event.Action,
			"subject", event.Subject,
			"error", lastErr,
		)
	}
}
