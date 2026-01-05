package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds Prometheus collectors for auth operations.
type Metrics struct {
	UsersCreated            prometheus.Counter
	ActiveSessions          prometheus.Gauge
	TokenRequests           prometheus.Counter
	AuthFailures            prometheus.Counter
	LogoutAllSessions       prometheus.Histogram
	LogoutAllDurationMs     prometheus.Histogram
	RateLimitCheckErrors    *prometheus.CounterVec
	AuthorizeDurationMs     prometheus.Histogram
	TokenExchangeDurationMs prometheus.Histogram
	TokenRefreshDurationMs  prometheus.Histogram

	// PRD-020 FR-0: SLI metrics with tenant/client labels
	AuthorizeDurationByTenant     *prometheus.HistogramVec
	TokenExchangeDurationByTenant *prometheus.HistogramVec
	TokenRefreshDurationByTenant  *prometheus.HistogramVec
	AuthErrorsByEndpoint          *prometheus.CounterVec

	// PRD-020 FR-0: TRL health metrics
	TRLWriteFailures     prometheus.Counter
	RevocationLagSeconds prometheus.Gauge

	// PRD-020 FR-0: Abuse signal metrics
	RefreshTokenReuseDetections prometheus.Counter
}

// New registers and returns auth metrics collectors.
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
		AuthorizeDurationMs: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "credo_authorize_duration_ms",
			Help:    "Duration of authorization requests in milliseconds",
			Buckets: []float64{5, 10, 25, 50, 100, 250, 500, 1000},
		}),
		TokenExchangeDurationMs: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "credo_token_exchange_duration_ms",
			Help:    "Duration of authorization code exchange in milliseconds",
			Buckets: []float64{5, 10, 25, 50, 100, 250, 500, 1000},
		}),
		TokenRefreshDurationMs: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "credo_token_refresh_duration_ms",
			Help:    "Duration of token refresh operations in milliseconds",
			Buckets: []float64{5, 10, 25, 50, 100, 250, 500, 1000},
		}),

		// PRD-020 FR-0: SLI metrics with tenant/client labels
		AuthorizeDurationByTenant: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "credo_authorize_duration_by_tenant_ms",
			Help:    "Duration of authorization requests in milliseconds, by tenant and client",
			Buckets: []float64{5, 10, 25, 50, 100, 250, 500, 1000},
		}, []string{"tenant_id", "client_id"}),
		TokenExchangeDurationByTenant: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "credo_token_exchange_duration_by_tenant_ms",
			Help:    "Duration of authorization code exchange in milliseconds, by tenant and client",
			Buckets: []float64{5, 10, 25, 50, 100, 250, 500, 1000},
		}, []string{"tenant_id", "client_id"}),
		TokenRefreshDurationByTenant: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "credo_token_refresh_duration_by_tenant_ms",
			Help:    "Duration of token refresh operations in milliseconds, by tenant and client",
			Buckets: []float64{5, 10, 25, 50, 100, 250, 500, 1000},
		}, []string{"tenant_id", "client_id"}),
		AuthErrorsByEndpoint: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "credo_auth_errors_by_endpoint_total",
			Help: "Total number of auth errors by endpoint, tenant, and client",
		}, []string{"endpoint", "tenant_id", "client_id"}),

		// PRD-020 FR-0: TRL health metrics
		TRLWriteFailures: promauto.NewCounter(prometheus.CounterOpts{
			Name: "credo_trl_write_failures_total",
			Help: "Total number of token revocation list write failures",
		}),
		RevocationLagSeconds: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "credo_revocation_lag_seconds",
			Help: "Age in seconds of the oldest unprocessed revocation",
		}),

		// PRD-020 FR-0: Abuse signal metrics
		RefreshTokenReuseDetections: promauto.NewCounter(prometheus.CounterOpts{
			Name: "credo_refresh_token_reuse_detections_total",
			Help: "Total number of refresh token reuse (replay) detections",
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

func (m *Metrics) ObserveLogoutAll(sessionCount int, durationMs float64) {
	m.LogoutAllSessions.Observe(float64(sessionCount))
	m.LogoutAllDurationMs.Observe(durationMs)
}

func (m *Metrics) IncrementRateLimitCheckErrors(endpoint string) {
	m.RateLimitCheckErrors.WithLabelValues(endpoint).Inc()
}

func (m *Metrics) ObserveAuthorizeDuration(durationMs float64) {
	m.AuthorizeDurationMs.Observe(durationMs)
}

func (m *Metrics) ObserveTokenExchangeDuration(durationMs float64) {
	m.TokenExchangeDurationMs.Observe(durationMs)
}

func (m *Metrics) ObserveTokenRefreshDuration(durationMs float64) {
	m.TokenRefreshDurationMs.Observe(durationMs)
}

// PRD-020 FR-0: SLI metrics with tenant/client labels

func (m *Metrics) ObserveAuthorizeDurationByTenant(tenantID, clientID string, durationMs float64) {
	m.AuthorizeDurationByTenant.WithLabelValues(tenantID, clientID).Observe(durationMs)
}

func (m *Metrics) ObserveTokenExchangeDurationByTenant(tenantID, clientID string, durationMs float64) {
	m.TokenExchangeDurationByTenant.WithLabelValues(tenantID, clientID).Observe(durationMs)
}

func (m *Metrics) ObserveTokenRefreshDurationByTenant(tenantID, clientID string, durationMs float64) {
	m.TokenRefreshDurationByTenant.WithLabelValues(tenantID, clientID).Observe(durationMs)
}

func (m *Metrics) IncrementAuthErrorsByEndpoint(endpoint, tenantID, clientID string) {
	m.AuthErrorsByEndpoint.WithLabelValues(endpoint, tenantID, clientID).Inc()
}

// PRD-020 FR-0: TRL health metrics

func (m *Metrics) IncrementTRLWriteFailures() {
	m.TRLWriteFailures.Inc()
}

func (m *Metrics) SetRevocationLag(seconds float64) {
	m.RevocationLagSeconds.Set(seconds)
}

// PRD-020 FR-0: Abuse signal metrics

func (m *Metrics) IncrementRefreshTokenReuseDetections() {
	m.RefreshTokenReuseDetections.Inc()
}
