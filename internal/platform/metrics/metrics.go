package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metrics for the application
type Metrics struct {
	UsersCreated    prometheus.Counter
	ActiveSessions  prometheus.Gauge
	TokenRequests   prometheus.Counter
	AuthFailures    prometheus.Counter
	EndpointLatency *prometheus.HistogramVec
	// Consent metrics
	ConsentsGranted       *prometheus.CounterVec
	ConsentsRevoked       *prometheus.CounterVec
	ActiveConsentsPerUser prometheus.Gauge
	ConsentCheckPassed    *prometheus.CounterVec
	ConsentCheckFailed    *prometheus.CounterVec
	ConsentGrantLatency   prometheus.Histogram

	// Tenant metrics
	TenantCreated prometheus.Counter
}

// New creates and registers all Prometheus metrics
func New() *Metrics {
	return &Metrics{
		UsersCreated: promauto.NewCounter(prometheus.CounterOpts{
			Name: "credo_users_created_total",
			Help: "Total number of users created",
		}),
		TenantCreated: promauto.NewCounter(prometheus.CounterOpts{
			Name: "credo_tenants_created_total",
			Help: "Total number of tenants created",
		}),
		ActiveSessions: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "credo_active_sessions",
			Help: "Current number of active sessions",
		}),
		// 		- Token requests per minute (rate)
		TokenRequests: promauto.NewCounter(prometheus.CounterOpts{
			Name: "credo_token_requests_total",
			Help: "Total number of token requests",
		}),
		// - Auth failures per minute (rate)
		AuthFailures: promauto.NewCounter(prometheus.CounterOpts{
			Name: "credo_auth_failures_total",
			Help: "Total number of authentication failures",
		}),
		// - Latency per endpoint (histogram)
		EndpointLatency: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "credo_endpoint_latency_seconds",
			Help:    "Latency of endpoints in seconds",
			Buckets: prometheus.DefBuckets,
		}, []string{"endpoint"}),
		// Consent metrics
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

// IncrementUsersCreated increments the users created counter by 1
func (m *Metrics) IncrementUsersCreated() {
	m.UsersCreated.Inc()
}

func (m *Metrics) IncrementActiveSessions(count int) {
	m.ActiveSessions.Add(float64(count))
}
func (m *Metrics) DecrementActiveSessions(count int) {
	m.ActiveSessions.Sub(float64(count))
}
func (m *Metrics) IncrementTokenRequests() {
	m.TokenRequests.Inc()
}
func (m *Metrics) IncrementAuthFailures() {
	m.AuthFailures.Inc()
}

// ObserveEndpointLatency records the latency for a given endpoint

func (m *Metrics) ObserveEndpointLatency(endpoint string, durationSeconds float64) {
	m.EndpointLatency.WithLabelValues(endpoint).Observe(durationSeconds)
}

// IncrementConsentsGranted increments the consents granted counter with purpose label
func (m *Metrics) IncrementConsentsGranted(purpose string) {
	m.ConsentsGranted.WithLabelValues(purpose).Inc()
}

// IncrementConsentsRevoked increments the consents revoked counter with purpose label
func (m *Metrics) IncrementConsentsRevoked(purpose string) {
	m.ConsentsRevoked.WithLabelValues(purpose).Inc()
}

// IncrementConsentCheckPassed increments the consent check passed counter with purpose label
func (m *Metrics) IncrementConsentCheckPassed(purpose string) {
	m.ConsentCheckPassed.WithLabelValues(purpose).Inc()
}

// IncrementConsentCheckFailed increments the consent check failed counter with purpose label
func (m *Metrics) IncrementConsentCheckFailed(purpose string) {
	m.ConsentCheckFailed.WithLabelValues(purpose).Inc()
}

// IncrementActiveConsentsPerUser increments the active consents per user gauge
func (m *Metrics) IncrementActiveConsentsPerUser(count float64) {
	m.ActiveConsentsPerUser.Add(count)
}

// DecrementActiveConsentsPerUser decrements the active consents per user gauge
func (m *Metrics) DecrementActiveConsentsPerUser(count float64) {
	m.ActiveConsentsPerUser.Sub(count)
}

// ObserveConsentGrantLatency records the latency for consent grant operations
func (m *Metrics) ObserveConsentGrantLatency(durationSeconds float64) {
	m.ConsentGrantLatency.Observe(durationSeconds)
}
