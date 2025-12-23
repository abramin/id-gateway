package publisher

import (
	"context"
	"log/slog"
	"sync"
	"time"

	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	audit "credo/pkg/platform/audit"
)

// Publisher captures structured audit events. It is append-only and uses the
// storage layer for persistence so tests can swap sinks easily.
type Publisher struct {
	store  audit.Store
	events chan audit.Event
	wg     sync.WaitGroup
	logger *slog.Logger
	async  bool
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

func NewPublisher(store audit.Store, opts ...PublisherOption) *Publisher {
	p := &Publisher{store: store}
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
func (p *Publisher) processEvents() {
	defer p.wg.Done()
	for event := range p.events {
		if err := p.store.Append(context.Background(), event); err != nil {
			if p.logger != nil {
				p.logger.Error("failed to persist audit event",
					"error", err,
					"action", event.Action,
					"user_id", event.UserID,
				)
			}
		}
	}
}

// Close shuts down the async publisher and waits for pending events to drain.
func (p *Publisher) Close() {
	if p.async && p.events != nil {
		close(p.events)
		p.wg.Wait()
	}
}

func (p *Publisher) Emit(ctx context.Context, base audit.Event) error {
	if base.Timestamp.IsZero() {
		base.Timestamp = time.Now()
	}
	if p.async {
		// Non-blocking send with context cancellation support
		select {
		case p.events <- base:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		default:
			if p.logger != nil {
				p.logger.Warn("audit buffer full, event dropped",
					"action", base.Action,
					"user_id", base.UserID,
				)
			}
			return dErrors.New(dErrors.CodeInternal, "audit buffer full")
		}
	}
	return p.store.Append(ctx, base)
}

func (p *Publisher) List(ctx context.Context, userID id.UserID) ([]audit.Event, error) {
	return p.store.ListByUser(ctx, userID)
}
