package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds Prometheus collectors for consent operations.
type Metrics struct {
	ConsentsGranted       *prometheus.CounterVec
	ConsentsRevoked       *prometheus.CounterVec
	ActiveConsentsTotal prometheus.Gauge
	ConsentCheckPassed    *prometheus.CounterVec
	ConsentCheckFailed    *prometheus.CounterVec
	ConsentGrantLatency   prometheus.Histogram

	// Performance metrics
	StoreOperationLatency *prometheus.HistogramVec
	RecordsPerUser        prometheus.Histogram
}

// New registers and returns consent metrics collectors.
func New() *Metrics {
	return &Metrics{
		ConsentsGranted: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "credo_consents_granted_total",
			Help: "Total number of consents granted, labeled by purpose",
		}, []string{"purpose"}),
		ConsentsRevoked: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "credo_consents_revoked_total",
			Help: "Total number of consents revoked, labeled by purpose",
		}, []string{"purpose"}),
		ActiveConsentsTotal: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "credo_active_consents_total",
			Help: "Current number of active consents system-wide",
		}),
		ConsentCheckPassed: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "credo_consent_checks_passed_total",
			Help: "Total number of consent checks that passed, labeled by purpose",
		}, []string{"purpose"}),
		ConsentCheckFailed: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "credo_consent_checks_failed_total",
			Help: "Total number of consent checks that failed, labeled by purpose",
		}, []string{"purpose"}),
		ConsentGrantLatency: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "credo_consent_grant_latency_seconds",
			Help:    "Latency of consent grant operations in seconds",
			Buckets: prometheus.DefBuckets,
		}),

		// Performance metrics
		StoreOperationLatency: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "credo_consent_store_operation_latency_seconds",
			Help:    "Latency of consent store operations in seconds",
			Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
		}, []string{"operation"}),
		RecordsPerUser: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "credo_consent_records_per_user",
			Help:    "Distribution of consent record counts per user",
			Buckets: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000},
		}),
	}
}

func (m *Metrics) IncrementConsentsGranted(purpose string) {
	m.ConsentsGranted.WithLabelValues(purpose).Inc()
}

func (m *Metrics) IncrementConsentsRevoked(purpose string) {
	m.ConsentsRevoked.WithLabelValues(purpose).Inc()
}

func (m *Metrics) IncrementConsentCheckPassed(purpose string) {
	m.ConsentCheckPassed.WithLabelValues(purpose).Inc()
}

func (m *Metrics) IncrementConsentCheckFailed(purpose string) {
	m.ConsentCheckFailed.WithLabelValues(purpose).Inc()
}

func (m *Metrics) IncrementActiveConsents(count float64) {
	m.ActiveConsentsTotal.Add(count)
}

func (m *Metrics) DecrementActiveConsents(count float64) {
	m.ActiveConsentsTotal.Sub(count)
}

func (m *Metrics) ObserveConsentGrantLatency(durationSeconds float64) {
	m.ConsentGrantLatency.Observe(durationSeconds)
}

// ObserveStoreOperationLatency records the latency of a store operation.
func (m *Metrics) ObserveStoreOperationLatency(operation string, durationSeconds float64) {
	m.StoreOperationLatency.WithLabelValues(operation).Observe(durationSeconds)
}

// ObserveRecordsPerUser records the number of consent records for a user.
func (m *Metrics) ObserveRecordsPerUser(count float64) {
	m.RecordsPerUser.Observe(count)
}
