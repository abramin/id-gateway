package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Metrics struct {
	UsersCreated         prometheus.Counter
	ActiveSessions       prometheus.Gauge
	TokenRequests        prometheus.Counter
	AuthFailures         prometheus.Counter
	LogoutAllSessions    prometheus.Histogram
	LogoutAllDurationMs  prometheus.Histogram
	RateLimitCheckErrors *prometheus.CounterVec
}

func New() *Metrics {
	return &Metrics{
		UsersCreated: promauto.NewCounter(prometheus.CounterOpts{
			Name: "credo_users_created_total",
			Help: "Total number of users created",
		}),
		ActiveSessions: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "credo_active_sessions",
			Help: "Current number of active sessions",
		}),
		TokenRequests: promauto.NewCounter(prometheus.CounterOpts{
			Name: "credo_token_requests_total",
			Help: "Total number of token requests",
		}),
		AuthFailures: promauto.NewCounter(prometheus.CounterOpts{
			Name: "credo_auth_failures_total",
			Help: "Total number of authentication failures",
		}),
		LogoutAllSessions: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "credo_logout_all_sessions",
			Help:    "Number of sessions revoked per logout-all operation",
			Buckets: []float64{1, 2, 5, 10, 20, 50, 100},
		}),
		LogoutAllDurationMs: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "credo_logout_all_duration_ms",
			Help:    "Duration of logout-all operations in milliseconds",
			Buckets: []float64{10, 50, 100, 250, 500, 1000, 2500, 5000},
		}),
		RateLimitCheckErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "credo_ratelimit_check_errors_total",
			Help: "Total number of rate limit check failures (fail-open events)",
		}, []string{"endpoint"}),
	}
}

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

func (m *Metrics) ObserveLogoutAll(sessionCount int, durationMs float64) {
	m.LogoutAllSessions.Observe(float64(sessionCount))
	m.LogoutAllDurationMs.Observe(durationMs)
}

func (m *Metrics) IncrementRateLimitCheckErrors(endpoint string) {
	m.RateLimitCheckErrors.WithLabelValues(endpoint).Inc()
}
