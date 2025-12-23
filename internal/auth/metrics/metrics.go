package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Metrics struct {
	UsersCreated   prometheus.Counter
	ActiveSessions prometheus.Gauge
	TokenRequests  prometheus.Counter
	AuthFailures   prometheus.Counter
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
