package publisher

import (
	"context"
	"log/slog"
	"time"

	id "credo/pkg/domain"
	audit "credo/pkg/platform/audit"
	"credo/pkg/platform/audit/metrics"
)

// Publisher captures structured audit events using the configured store.
// In production, the store writes to the outbox for Kafka publishing.
type Publisher struct {
	store   audit.Store
	logger  *slog.Logger
	metrics *metrics.Metrics
}

// PublisherOption configures the Publisher.
type PublisherOption func(*Publisher)

// WithPublisherLogger sets a logger for persistence error reporting.
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
	p := &Publisher{
		store:  store,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Close is a no-op for the synchronous publisher.
func (p *Publisher) Close() {
}

func (p *Publisher) Emit(ctx context.Context, base audit.Event) error {
	start := time.Now()

	if base.Timestamp.IsZero() {
		base.Timestamp = time.Now()
	}

	// Synchronous write directly to store (outbox-backed in production).
	err := p.store.Append(ctx, base)
	if p.metrics != nil {
		elapsed := time.Since(start).Seconds()
		p.metrics.ObserveEmitDuration(elapsed)
		p.metrics.ObservePersistDuration(elapsed)
		if err != nil {
			p.metrics.IncPersistFailures()
		} else {
			p.metrics.IncEventsProcessed()
		}
	}
	if err != nil && p.logger != nil {
		p.logger.Error("failed to persist audit event",
			"error", err,
			"action", base.Action,
			"user_id", base.UserID,
		)
	}
	return err
}

func (p *Publisher) List(ctx context.Context, userID id.UserID) ([]audit.Event, error) {
	return p.store.ListByUser(ctx, userID)
}
