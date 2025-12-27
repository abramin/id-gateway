package publisher

import (
	"context"
	"log/slog"
	"sync"
	"time"

	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	audit "credo/pkg/platform/audit"
	"credo/pkg/platform/audit/metrics"
)

// Publisher captures structured audit events. It is append-only and uses the
// storage layer for persistence so tests can swap sinks easily.
type Publisher struct {
	store   audit.Store
	events  chan audit.Event
	wg      sync.WaitGroup
	logger  *slog.Logger
	metrics *metrics.Metrics
	async   bool
	ctx     context.Context
	cancel  context.CancelFunc
}

// PublisherOption configures the Publisher.
type PublisherOption func(*Publisher)

// WithAsyncBuffer enables async processing with the specified buffer size.
// Events are queued and persisted in a background goroutine.
func WithAsyncBuffer(size int) PublisherOption {
	return func(p *Publisher) {
		if size > 0 {
			p.events = make(chan audit.Event, size)
			p.async = true
		}
	}
}

// WithPublisherLogger sets a logger for async error reporting.
func WithPublisherLogger(logger *slog.Logger) PublisherOption {
	return func(p *Publisher) {
		p.logger = logger
	}
}

// WithMetrics sets the metrics collector for the publisher.
func WithMetrics(m *metrics.Metrics) PublisherOption {
	return func(p *Publisher) {
		p.metrics = m
	}
}

func NewPublisher(store audit.Store, opts ...PublisherOption) *Publisher {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Publisher{
		store:  store,
		ctx:    ctx,
		cancel: cancel,
	}
	for _, opt := range opts {
		opt(p)
	}
	if p.async {
		p.wg.Add(1)
		go p.processEvents()
	}
	return p
}

// processEvents runs in a goroutine and persists events from the channel.
// It respects context cancellation and drains remaining events on shutdown.
func (p *Publisher) processEvents() {
	defer p.wg.Done()
	for {
		select {
		case <-p.ctx.Done():
			// Drain remaining events on shutdown
			p.drainEvents()
			return
		case event, ok := <-p.events:
			if !ok {
				return
			}
			p.persistEvent(event, false)
		}
	}
}

// drainEvents persists any remaining events in the channel during shutdown.
func (p *Publisher) drainEvents() {
	for {
		select {
		case event, ok := <-p.events:
			if !ok {
				return
			}
			p.persistEvent(event, true)
		default:
			return
		}
	}
}

// persistEvent writes a single event to the store with metrics tracking.
func (p *Publisher) persistEvent(event audit.Event, isDrain bool) {
	start := time.Now()

	if p.metrics != nil {
		p.metrics.DecQueueDepth()
	}

	if err := p.store.Append(p.ctx, event); err != nil {
		if p.metrics != nil {
			p.metrics.IncPersistFailures()
		}
		if p.logger != nil {
			p.logger.Error("failed to persist audit event",
				"error", err,
				"action", event.Action,
				"user_id", event.UserID,
			)
		}
		return
	}

	if p.metrics != nil {
		p.metrics.ObservePersistDuration(time.Since(start).Seconds())
		p.metrics.IncEventsProcessed()
		if isDrain {
			p.metrics.IncWorkerDrainEvents()
		}
	}
}

// Close shuts down the async publisher and waits for pending events to drain.
func (p *Publisher) Close() {
	if p.async && p.events != nil {
		p.cancel() // Signal worker to stop accepting new events and drain
		close(p.events)
		p.wg.Wait()
	}
}

func (p *Publisher) Emit(ctx context.Context, base audit.Event) error {
	start := time.Now()

	if base.Timestamp.IsZero() {
		base.Timestamp = time.Now()
	}

	if p.async {
		// Non-blocking send with context cancellation support
		select {
		case p.events <- base:
			if p.metrics != nil {
				p.metrics.ObserveEmitDuration(time.Since(start).Seconds())
				p.metrics.IncQueueDepth()
				p.metrics.IncEventsEnqueued()
			}
			return nil
		case <-ctx.Done():
			return ctx.Err()
		default:
			if p.metrics != nil {
				p.metrics.IncEventsDropped()
			}
			if p.logger != nil {
				p.logger.Warn("audit buffer full, event dropped",
					"action", base.Action,
					"user_id", base.UserID,
				)
			}
			return dErrors.New(dErrors.CodeInternal, "audit buffer full")
		}
	}

	// Synchronous mode: write directly to store
	err := p.store.Append(ctx, base)
	if p.metrics != nil {
		p.metrics.ObserveEmitDuration(time.Since(start).Seconds())
		if err != nil {
			p.metrics.IncPersistFailures()
		} else {
			p.metrics.IncEventsProcessed()
		}
	}
	return err
}

func (p *Publisher) List(ctx context.Context, userID id.UserID) ([]audit.Event, error) {
	return p.store.ListByUser(ctx, userID)
}
