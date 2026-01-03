package security

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds Prometheus metrics for security audit emission.
type Metrics struct {
	QueueDepth        prometheus.Gauge
	Flushed           prometheus.Counter
	Dropped           prometheus.Counter
	DroppedAfterRetry prometheus.Counter
	Retries           prometheus.Counter
	FlushDuration     prometheus.Histogram
}

var (
	metricsOnce     sync.Once
	metricsInstance *Metrics
)

// NewMetrics returns the singleton Metrics instance with security audit metrics registered.
// Safe to call multiple times; metrics are only registered once.
func NewMetrics() *Metrics {
	metricsOnce.Do(func() {
		metricsInstance = &Metrics{
			QueueDepth: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "credo_audit_security_queue_depth",
				Help: "Current number of security events in the buffer",
			}),
			Flushed: promauto.NewCounter(prometheus.CounterOpts{
				Name: "credo_audit_security_flushed_total",
				Help: "Total number of security audit events successfully flushed",
			}),
			Dropped: promauto.NewCounter(prometheus.CounterOpts{
				Name: "credo_audit_security_dropped_total",
				Help: "Total number of security audit events dropped due to buffer overflow",
			}),
			DroppedAfterRetry: promauto.NewCounter(prometheus.CounterOpts{
				Name: "credo_audit_security_dropped_after_retry_total",
				Help: "Total number of security audit events dropped after exhausting retries",
			}),
			Retries: promauto.NewCounter(prometheus.CounterOpts{
				Name: "credo_audit_security_retries_total",
				Help: "Total number of retry attempts for security audit events",
			}),
			FlushDuration: promauto.NewHistogram(prometheus.HistogramOpts{
				Name:    "credo_audit_security_flush_duration_seconds",
				Help:    "Time taken to flush a batch of security audit events",
				Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
			}),
		}
	})
	return metricsInstance
}

// SetQueueDepth sets the current queue depth.
func (m *Metrics) SetQueueDepth(depth int64) {
	m.QueueDepth.Set(float64(depth))
}

// IncFlushed increments the flushed counter.
func (m *Metrics) IncFlushed() {
	m.Flushed.Inc()
}

// IncDropped increments the dropped counter.
func (m *Metrics) IncDropped() {
	m.Dropped.Inc()
}

// IncDroppedAfterRetry increments the dropped-after-retry counter.
func (m *Metrics) IncDroppedAfterRetry() {
	m.DroppedAfterRetry.Inc()
}

// IncRetries increments the retries counter.
func (m *Metrics) IncRetries() {
	m.Retries.Inc()
}

// ObserveFlushDuration records the flush operation latency.
func (m *Metrics) ObserveFlushDuration(durationSeconds float64) {
	m.FlushDuration.Observe(durationSeconds)
}
