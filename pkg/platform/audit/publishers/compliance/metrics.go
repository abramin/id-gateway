package compliance

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds Prometheus metrics for compliance audit emission.
type Metrics struct {
	PersistDuration prometheus.Histogram
	PersistFailures prometheus.Counter
	EventsEmitted   prometheus.Counter
}

var (
	metricsOnce     sync.Once
	metricsInstance *Metrics
)

// NewMetrics returns the singleton Metrics instance with compliance audit metrics registered.
// Safe to call multiple times; metrics are only registered once.
func NewMetrics() *Metrics {
	metricsOnce.Do(func() {
		metricsInstance = &Metrics{
			PersistDuration: promauto.NewHistogram(prometheus.HistogramOpts{
				Name:    "credo_audit_compliance_persist_duration_seconds",
				Help:    "Time taken to persist a compliance audit event",
				Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
			}),
			PersistFailures: promauto.NewCounter(prometheus.CounterOpts{
				Name: "credo_audit_compliance_persist_failures_total",
				Help: "Total number of compliance audit event persistence failures (CRITICAL)",
			}),
			EventsEmitted: promauto.NewCounter(prometheus.CounterOpts{
				Name: "credo_audit_compliance_events_emitted_total",
				Help: "Total number of compliance audit events successfully emitted",
			}),
		}
	})
	return metricsInstance
}

// ObservePersistDuration records the persist operation latency.
func (m *Metrics) ObservePersistDuration(durationSeconds float64) {
	m.PersistDuration.Observe(durationSeconds)
}

// IncPersistFailures increments the persist failures counter.
func (m *Metrics) IncPersistFailures() {
	m.PersistFailures.Inc()
}

// IncEventsEmitted increments the emitted events counter.
func (m *Metrics) IncEventsEmitted() {
	m.EventsEmitted.Inc()
}
