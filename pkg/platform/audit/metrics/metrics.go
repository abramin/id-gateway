package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds Prometheus metrics for audit event emission.
type Metrics struct {
	EmitDuration    prometheus.Histogram
	PersistDuration prometheus.Histogram
	PersistFailures prometheus.Counter
	EventsProcessed prometheus.Counter
}

// New creates a new Metrics instance with audit emission metrics registered.
func New() *Metrics {
	return &Metrics{
		EmitDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "credo_audit_emit_duration_seconds",
			Help:    "Time taken to emit an audit event",
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
			Help: "Total number of audit events successfully persisted to the store",
		}),
	}
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
