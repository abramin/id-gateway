package ops

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds Prometheus metrics for ops audit tracking.
type Metrics struct {
	Tracked               prometheus.Counter
	Sampled               prometheus.Counter
	CircuitBreakerDropped prometheus.Counter
	PersistFailures       prometheus.Counter
	CircuitBreakerState   prometheus.Gauge
}

var (
	metricsOnce     sync.Once
	metricsInstance *Metrics
)

// NewMetrics returns the singleton Metrics instance with ops audit metrics registered.
// Safe to call multiple times; metrics are only registered once.
func NewMetrics() *Metrics {
	metricsOnce.Do(func() {
		metricsInstance = &Metrics{
			Tracked: promauto.NewCounter(prometheus.CounterOpts{
				Name: "credo_audit_ops_tracked_total",
				Help: "Total number of operational audit events successfully tracked",
			}),
			Sampled: promauto.NewCounter(prometheus.CounterOpts{
				Name: "credo_audit_ops_sampled_total",
				Help: "Total number of operational audit events dropped due to sampling",
			}),
			CircuitBreakerDropped: promauto.NewCounter(prometheus.CounterOpts{
				Name: "credo_audit_ops_circuit_breaker_dropped_total",
				Help: "Total number of operational audit events dropped due to circuit breaker",
			}),
			PersistFailures: promauto.NewCounter(prometheus.CounterOpts{
				Name: "credo_audit_ops_persist_failures_total",
				Help: "Total number of operational audit event persistence failures",
			}),
			CircuitBreakerState: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "credo_audit_ops_circuit_breaker_state",
				Help: "Current circuit breaker state (0=closed/healthy, 1=open/unhealthy)",
			}),
		}
	})
	return metricsInstance
}

// IncTracked increments the tracked counter.
func (m *Metrics) IncTracked() {
	m.Tracked.Inc()
}

// IncSampled increments the sampled counter.
func (m *Metrics) IncSampled() {
	m.Sampled.Inc()
}

// IncCircuitBreakerDropped increments the circuit breaker dropped counter.
func (m *Metrics) IncCircuitBreakerDropped() {
	m.CircuitBreakerDropped.Inc()
}

// IncPersistFailures increments the persist failures counter.
func (m *Metrics) IncPersistFailures() {
	m.PersistFailures.Inc()
}

// SetCircuitBreakerState sets the circuit breaker state gauge.
func (m *Metrics) SetCircuitBreakerState(open bool) {
	if open {
		m.CircuitBreakerState.Set(1)
	} else {
		m.CircuitBreakerState.Set(0)
	}
}
