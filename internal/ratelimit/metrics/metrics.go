package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Metrics struct {
	RateLimitAuthFailures                   prometheus.Counter
	RateLimitAuthLockoutsTotal              prometheus.Counter
	RateLimitAuthLockedIdentifiers          prometheus.Gauge
	RateLimitCleanupFailuresResetTotal      prometheus.Counter
	RateLimitCleanupDailyFailuresResetTotal prometheus.Counter
	RateLimitCleanupRunsTotal               *prometheus.CounterVec
	RateLimitCleanupDurationSeconds         prometheus.Histogram
}

func New() *Metrics {
	return &Metrics{
		RateLimitAuthFailures: promauto.NewCounter(prometheus.CounterOpts{
			Name: "credo_ratelimit_auth_failures_recorded_total",
			Help: "Total number of auth failures recorded for rate limiting",
		}),
		RateLimitAuthLockoutsTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "credo_ratelimit_auth_lockouts_total",
			Help:        "Total number of auth lockouts recorded for rate limiting",
			ConstLabels: prometheus.Labels{"type": "lockoutType"},
		}),
		RateLimitAuthLockedIdentifiers: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "credo_ratelimit_auth_locked_identifiers",
			Help: "Current number of hard locked identifiers due to rate limiting",
		}),
		RateLimitCleanupFailuresResetTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "credo_ratelimit_cleanup_failures_reset_total",
			Help: "Total number of auth lockout failures reset by the cleanup worker",
		}),
		RateLimitCleanupDailyFailuresResetTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "credo_ratelimit_cleanup_daily_failures_reset_total",
			Help: "Total number of daily auth lockout failures reset by the cleanup worker",
		}),
		RateLimitCleanupRunsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "credo_ratelimit_cleanup_runs_total",
			Help: "Total number of cleanup runs",
		}, []string{"status"}),
		RateLimitCleanupDurationSeconds: promauto.NewHistogram(prometheus.HistogramOpts{
			Name: "credo_ratelimit_cleanup_duration_seconds",
			Help: "Duration of cleanup runs in seconds",
		}),
	}
}

func (m *Metrics) IncrementAuthFailures() {
	m.RateLimitAuthFailures.Inc()
}

func (m *Metrics) IncrementAuthLockouts() {
	m.RateLimitAuthLockoutsTotal.Inc()
}

func (m *Metrics) SetLockedIdentifiers(count int) {
	m.RateLimitAuthLockedIdentifiers.Set(float64(count))
}

func (m *Metrics) IncrementCleanupFailuresReset(count int) {
	m.RateLimitCleanupFailuresResetTotal.Add(float64(count))
}
func (m *Metrics) IncrementCleanupDailyFailuresReset(count int) {
	m.RateLimitCleanupDailyFailuresResetTotal.Add(float64(count))
}

func (m *Metrics) IncrementCleanupRuns(status string) {
	m.RateLimitCleanupRunsTotal.WithLabelValues(status).Inc()
}
func (m *Metrics) ObserveCleanupDuration(durationSeconds float64) {
	m.RateLimitCleanupDurationSeconds.Observe(durationSeconds)
}
