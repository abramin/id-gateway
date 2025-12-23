package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Metrics struct {
	ConsentsGranted       *prometheus.CounterVec
	ConsentsRevoked       *prometheus.CounterVec
	ActiveConsentsPerUser prometheus.Gauge
	ConsentCheckPassed    *prometheus.CounterVec
	ConsentCheckFailed    *prometheus.CounterVec
	ConsentGrantLatency   prometheus.Histogram
}

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
		ActiveConsentsPerUser: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "credo_active_consents_per_user",
			Help: "Current number of active consents per user",
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

func (m *Metrics) IncrementActiveConsentsPerUser(count float64) {
	m.ActiveConsentsPerUser.Add(count)
}

func (m *Metrics) DecrementActiveConsentsPerUser(count float64) {
	m.ActiveConsentsPerUser.Sub(count)
}

func (m *Metrics) ObserveConsentGrantLatency(durationSeconds float64) {
	m.ConsentGrantLatency.Observe(durationSeconds)
}
