package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds Prometheus metrics for the outbox worker.
type Metrics struct {
	// Queue health metrics
	PendingDepth     prometheus.Gauge
	OldestPendingAge prometheus.Gauge

	// Processing metrics
	PublishedTotal  prometheus.Counter
	PublishFailures prometheus.Counter
	PublishDuration prometheus.Histogram
	BatchSize       prometheus.Histogram

	// Worker health metrics
	PollDuration   prometheus.Histogram
	WorkerRestarts prometheus.Counter
}

// New creates a new Metrics instance with all outbox metrics registered.
func New() *Metrics {
	return &Metrics{
		PendingDepth: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "credo_outbox_pending_total",
			Help: "Current number of pending (unprocessed) outbox entries",
		}),
		OldestPendingAge: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "credo_outbox_oldest_pending_seconds",
			Help: "Age in seconds of the oldest pending outbox entry",
		}),
		PublishedTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "credo_outbox_published_total",
			Help: "Total number of outbox entries successfully published to Kafka",
		}),
		PublishFailures: promauto.NewCounter(prometheus.CounterOpts{
			Name: "credo_outbox_publish_failures_total",
			Help: "Total number of outbox publish failures",
		}),
		PublishDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "credo_outbox_publish_duration_seconds",
			Help:    "Time taken to publish an outbox entry to Kafka",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
		}),
		BatchSize: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "credo_outbox_batch_size",
			Help:    "Number of entries processed per batch",
			Buckets: []float64{1, 5, 10, 25, 50, 100, 250, 500},
		}),
		PollDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "credo_outbox_poll_duration_seconds",
			Help:    "Time taken for each poll cycle",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
		}),
		WorkerRestarts: promauto.NewCounter(prometheus.CounterOpts{
			Name: "credo_outbox_worker_restarts_total",
			Help: "Total number of outbox worker restarts due to errors",
		}),
	}
}

// SetPendingDepth sets the current number of pending entries.
func (m *Metrics) SetPendingDepth(count int64) {
	m.PendingDepth.Set(float64(count))
}

// SetOldestPendingAge sets the age of the oldest pending entry in seconds.
func (m *Metrics) SetOldestPendingAge(ageSeconds float64) {
	m.OldestPendingAge.Set(ageSeconds)
}

// IncPublished increments the published counter.
func (m *Metrics) IncPublished() {
	m.PublishedTotal.Inc()
}

// IncPublishFailures increments the publish failures counter.
func (m *Metrics) IncPublishFailures() {
	m.PublishFailures.Inc()
}

// ObservePublishDuration records the publish operation latency.
func (m *Metrics) ObservePublishDuration(durationSeconds float64) {
	m.PublishDuration.Observe(durationSeconds)
}

// ObserveBatchSize records the size of a processed batch.
func (m *Metrics) ObserveBatchSize(size int) {
	m.BatchSize.Observe(float64(size))
}

// ObservePollDuration records the poll cycle latency.
func (m *Metrics) ObservePollDuration(durationSeconds float64) {
	m.PollDuration.Observe(durationSeconds)
}

// IncWorkerRestarts increments the worker restart counter.
func (m *Metrics) IncWorkerRestarts() {
	m.WorkerRestarts.Inc()
}
