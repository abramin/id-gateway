package worker

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"credo/internal/platform/kafka/producer"
	"credo/pkg/platform/audit/outbox"
	"credo/pkg/platform/audit/outbox/metrics"
)

// Worker polls the outbox table and publishes events to Kafka.
type Worker struct {
	store        outbox.Store
	producer     *producer.Producer
	topic        string
	batchSize    int
	pollInterval time.Duration
	metrics      *metrics.Metrics
	logger       *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Option configures the Worker.
type Option func(*Worker)

// WithTopic sets the Kafka topic for publishing.
func WithTopic(topic string) Option {
	return func(w *Worker) {
		w.topic = topic
	}
}

// WithBatchSize sets the maximum number of entries to fetch per poll.
func WithBatchSize(size int) Option {
	return func(w *Worker) {
		w.batchSize = size
	}
}

// WithPollInterval sets the interval between polls.
func WithPollInterval(interval time.Duration) Option {
	return func(w *Worker) {
		w.pollInterval = interval
	}
}

// WithMetrics sets the metrics collector.
func WithMetrics(m *metrics.Metrics) Option {
	return func(w *Worker) {
		w.metrics = m
	}
}

// WithLogger sets the logger.
func WithLogger(logger *slog.Logger) Option {
	return func(w *Worker) {
		w.logger = logger
	}
}

// New creates a new outbox worker.
func New(store outbox.Store, prod *producer.Producer, opts ...Option) *Worker {
	ctx, cancel := context.WithCancel(context.Background())

	w := &Worker{
		store:        store,
		producer:     prod,
		topic:        "credo.audit.events",
		batchSize:    100,
		pollInterval: 100 * time.Millisecond,
		ctx:          ctx,
		cancel:       cancel,
	}

	for _, opt := range opts {
		opt(w)
	}

	return w
}

// Start begins the polling loop in a background goroutine.
func (w *Worker) Start() {
	w.wg.Add(1)
	go w.run()
}

// run is the main polling loop.
func (w *Worker) run() {
	defer w.wg.Done()

	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			w.drain()
			return
		case <-ticker.C:
			w.poll()
		}
	}
}

// poll fetches and processes a batch of outbox entries.
func (w *Worker) poll() {
	start := time.Now()

	entries, err := w.store.FetchUnprocessed(w.ctx, w.batchSize)
	if err != nil {
		if w.logger != nil {
			w.logger.Error("failed to fetch outbox entries", "error", err)
		}
		if w.metrics != nil {
			w.metrics.IncPublishFailures()
		}
		return
	}

	if len(entries) == 0 {
		return
	}

	if w.metrics != nil {
		w.metrics.ObserveBatchSize(len(entries))
	}

	for _, entry := range entries {
		if err := w.publishEntry(entry); err != nil {
			if w.logger != nil {
				w.logger.Error("failed to publish outbox entry",
					"id", entry.ID,
					"event_type", entry.EventType,
					"error", err,
				)
			}
			if w.metrics != nil {
				w.metrics.IncPublishFailures()
			}
			// Continue with other entries; this one will be retried on next poll
			continue
		}

		// Mark as processed
		if err := w.store.MarkProcessed(w.ctx, entry.ID, time.Now()); err != nil {
			if w.logger != nil {
				w.logger.Error("failed to mark entry as processed",
					"id", entry.ID,
					"error", err,
				)
			}
			// Entry was published but not marked - will be re-published (idempotent consumer handles duplicates)
			continue
		}

		if w.metrics != nil {
			w.metrics.IncPublished()
		}
	}

	if w.metrics != nil {
		w.metrics.ObservePollDuration(time.Since(start).Seconds())
	}
}

// publishEntry publishes a single outbox entry to Kafka.
func (w *Worker) publishEntry(entry *outbox.Entry) error {
	start := time.Now()

	msg := &producer.Message{
		Topic: w.topic,
		Key:   []byte(entry.ID.String()), // Use entry ID as key for idempotency
		Value: entry.Payload,
		Headers: map[string]string{
			"aggregate_type": entry.AggregateType,
			"aggregate_id":   entry.AggregateID,
			"event_type":     entry.EventType,
		},
	}

	err := w.producer.Produce(w.ctx, msg)
	if err != nil {
		return err
	}

	if w.metrics != nil {
		w.metrics.ObservePublishDuration(time.Since(start).Seconds())
	}

	return nil
}

// drain processes remaining entries during shutdown.
func (w *Worker) drain() {
	if w.logger != nil {
		w.logger.Info("draining outbox worker")
	}

	// Use a short timeout context for draining
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for {
		entries, err := w.store.FetchUnprocessed(ctx, w.batchSize)
		if err != nil {
			if w.logger != nil {
				w.logger.Error("failed to fetch entries during drain", "error", err)
			}
			return
		}

		if len(entries) == 0 {
			return
		}

		for _, entry := range entries {
			if err := w.publishEntry(entry); err != nil {
				if w.logger != nil {
					w.logger.Error("failed to publish during drain",
						"id", entry.ID,
						"error", err,
					)
				}
				continue
			}

			if err := w.store.MarkProcessed(ctx, entry.ID, time.Now()); err != nil {
				if w.logger != nil {
					w.logger.Error("failed to mark as processed during drain",
						"id", entry.ID,
						"error", err,
					)
				}
			}
		}
	}
}

// Stop gracefully stops the worker.
func (w *Worker) Stop(ctx context.Context) error {
	w.cancel()

	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// UpdateMetrics updates the pending depth metric.
// Call this periodically from a separate goroutine if needed.
func (w *Worker) UpdateMetrics(ctx context.Context) error {
	if w.metrics == nil {
		return nil
	}

	count, err := w.store.CountPending(ctx)
	if err != nil {
		return err
	}

	w.metrics.SetPendingDepth(count)
	return nil
}
