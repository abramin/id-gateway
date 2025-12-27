package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds Prometheus metrics for the audit publisher.
type Metrics struct {
	// Queue metrics
	QueueDepth     prometheus.Gauge
	EventsDropped  prometheus.Counter
	EventsEnqueued prometheus.Counter

	// Processing metrics
	EmitDuration      prometheus.Histogram
	PersistDuration   prometheus.Histogram
	PersistFailures   prometheus.Counter
	EventsProcessed   prometheus.Counter
	WorkerDrainEvents prometheus.Counter
}

// New creates a new Metrics instance with all audit publisher metrics registered.
func New() *Metrics {
	return &Metrics{
		QueueDepth: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "credo_audit_queue_depth",
			Help: "Current number of events in the audit publisher queue",
		}),
		EventsDropped: promauto.NewCounter(prometheus.CounterOpts{
			Name: "credo_audit_events_dropped_total",
			Help: "Total number of audit events dropped due to full buffer",
		}),
		EventsEnqueued: promauto.NewCounter(prometheus.CounterOpts{
			Name: "credo_audit_events_enqueued_total",
			Help: "Total number of audit events successfully enqueued",
		}),
		EmitDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "credo_audit_emit_duration_seconds",
			Help:    "Time taken to emit an audit event (enqueue or sync write)",
			Buckets: []float64{0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1},
		}),
		PersistDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "credo_audit_persist_duration_seconds",
			Help:    "Time taken to persist an audit event to the store",
			Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
		}),
		PersistFailures: promauto.NewCounter(prometheus.CounterOpts{
			Name: "credo_audit_persist_failures_total",
			Help: "Total number of audit event persistence failures",
		}),
		EventsProcessed: promauto.NewCounter(prometheus.CounterOpts{
			Name: "credo_audit_events_processed_total",
			Help: "Total number of audit events successfully processed by the worker",
		}),
		WorkerDrainEvents: promauto.NewCounter(prometheus.CounterOpts{
			Name: "credo_audit_worker_drain_events_total",
			Help: "Total number of audit events drained during graceful shutdown",
		}),
	}
}

// IncQueueDepth increments the queue depth gauge.
func (m *Metrics) IncQueueDepth() {
	m.QueueDepth.Inc()
}

// DecQueueDepth decrements the queue depth gauge.
func (m *Metrics) DecQueueDepth() {
	m.QueueDepth.Dec()
}

// IncEventsDropped increments the dropped events counter.
func (m *Metrics) IncEventsDropped() {
	m.EventsDropped.Inc()
}

// IncEventsEnqueued increments the enqueued events counter.
func (m *Metrics) IncEventsEnqueued() {
	m.EventsEnqueued.Inc()
}

// ObserveEmitDuration records the emit operation latency.
func (m *Metrics) ObserveEmitDuration(durationSeconds float64) {
	m.EmitDuration.Observe(durationSeconds)
}

// ObservePersistDuration records the persist operation latency.
func (m *Metrics) ObservePersistDuration(durationSeconds float64) {
	m.PersistDuration.Observe(durationSeconds)
}

// IncPersistFailures increments the persist failures counter.
func (m *Metrics) IncPersistFailures() {
	m.PersistFailures.Inc()
}

// IncEventsProcessed increments the processed events counter.
func (m *Metrics) IncEventsProcessed() {
	m.EventsProcessed.Inc()
}

// IncWorkerDrainEvents increments the drain events counter.
func (m *Metrics) IncWorkerDrainEvents() {
	m.WorkerDrainEvents.Inc()
}
