// Package metrics provides Prometheus metrics for the rate limiting module (PRD-017 FR-8).
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics contains all rate limiting metrics as defined in PRD-017 FR-8.
type Metrics struct {
	// Request-level metrics
	RequestsTotal          *prometheus.CounterVec   // All rate limit checks (class, decision)
	BlocksTotal            *prometheus.CounterVec   // Blocked requests by limit type
	AllowlistBypassesTotal *prometheus.CounterVec   // Requests bypassed via allowlist (type)
	CheckDurationSeconds   *prometheus.HistogramVec // Rate limit check latency (class)

	// Auth lockout metrics
	RateLimitAuthFailures          prometheus.Counter
	RateLimitAuthLockoutsTotal     *prometheus.CounterVec // (type: soft/hard)
	RateLimitAuthLockedIdentifiers prometheus.Gauge

	// Quota metrics
	QuotaUsageTotal    *prometheus.CounterVec // API quota increments by tier
	QuotaExceededTotal *prometheus.CounterVec // Quota exceeded events by tier

	// Store-level gauges
	BucketEntries      prometheus.Gauge
	AllowlistEntries   *prometheus.GaugeVec // (type: ip/user_id)
	AuthLockoutRecords prometheus.Gauge

	// Cleanup worker metrics
	RateLimitCleanupFailuresResetTotal      prometheus.Counter
	RateLimitCleanupDailyFailuresResetTotal prometheus.Counter
	RateLimitCleanupRunsTotal               *prometheus.CounterVec
	RateLimitCleanupDurationSeconds         prometheus.Histogram
	CleanupEntriesRemovedTotal              *prometheus.CounterVec // (type)
}

// New creates a new Metrics instance with all metrics registered.
func New() *Metrics {
	return &Metrics{
		// Request-level metrics (PRD-017 FR-8)
		RequestsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "credo_ratelimit_requests_total",
			Help: "Total number of rate limit checks by endpoint class and decision",
		}, []string{"class", "decision"}),

		BlocksTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "credo_ratelimit_blocks_total",
			Help: "Total number of blocked requests by limit type",
		}, []string{"limit_type"}),

		AllowlistBypassesTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "credo_ratelimit_allowlist_bypasses_total",
			Help: "Total number of requests that bypassed rate limiting via allowlist",
		}, []string{"type"}),

		CheckDurationSeconds: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "credo_ratelimit_check_duration_seconds",
			Help:    "Duration of rate limit checks by endpoint class",
			Buckets: prometheus.DefBuckets,
		}, []string{"class"}),

		// Auth lockout metrics
		RateLimitAuthFailures: promauto.NewCounter(prometheus.CounterOpts{
			Name: "credo_ratelimit_auth_failures_recorded_total",
			Help: "Total number of auth failures recorded for rate limiting",
		}),

		RateLimitAuthLockoutsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "credo_ratelimit_auth_lockouts_total",
			Help: "Total number of auth lockouts (soft=CAPTCHA required, hard=access denied)",
		}, []string{"type"}),

		RateLimitAuthLockedIdentifiers: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "credo_ratelimit_auth_locked_identifiers",
			Help: "Current number of hard locked identifiers due to rate limiting",
		}),

		// Quota metrics
		QuotaUsageTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "credo_ratelimit_quota_usage_total",
			Help: "API quota increments by tier",
		}, []string{"tier"}),

		QuotaExceededTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "credo_ratelimit_quota_exceeded_total",
			Help: "Quota exceeded events by tier",
		}, []string{"tier"}),

		// Store-level gauges
		BucketEntries: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "credo_ratelimit_bucket_entries",
			Help: "Current number of active rate limit buckets in memory",
		}),

		AllowlistEntries: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "credo_ratelimit_allowlist_entries",
			Help: "Current number of allowlist entries by type",
		}, []string{"type"}),

		AuthLockoutRecords: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "credo_ratelimit_authlockout_records",
			Help: "Current number of auth lockout records in store",
		}),

		// Cleanup worker metrics
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
			Help: "Total number of cleanup runs by status",
		}, []string{"status"}),

		RateLimitCleanupDurationSeconds: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "credo_ratelimit_cleanup_duration_seconds",
			Help:    "Duration of cleanup runs in seconds",
			Buckets: prometheus.DefBuckets,
		}),

		CleanupEntriesRemovedTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "credo_ratelimit_cleanup_entries_removed_total",
			Help: "Total number of entries removed during cleanup by type",
		}, []string{"type"}),
	}
}

// Helper methods for incrementing metrics

// RecordRequest records a rate limit check with the given class and decision.
func (m *Metrics) RecordRequest(class, decision string) {
	m.RequestsTotal.WithLabelValues(class, decision).Inc()
}

// RecordBlock records a blocked request with the given limit type.
func (m *Metrics) RecordBlock(limitType string) {
	m.BlocksTotal.WithLabelValues(limitType).Inc()
}

// RecordAllowlistBypass records an allowlist bypass with the given type.
func (m *Metrics) RecordAllowlistBypass(bypassType string) {
	m.AllowlistBypassesTotal.WithLabelValues(bypassType).Inc()
}

// ObserveCheckDuration records the duration of a rate limit check.
func (m *Metrics) ObserveCheckDuration(class string, durationSeconds float64) {
	m.CheckDurationSeconds.WithLabelValues(class).Observe(durationSeconds)
}

// IncrementAuthFailures increments the auth failures counter.
func (m *Metrics) IncrementAuthFailures() {
	m.RateLimitAuthFailures.Inc()
}

// IncrementAuthLockouts increments the auth lockouts counter with the given type (soft/hard).
func (m *Metrics) IncrementAuthLockouts(lockoutType string) {
	m.RateLimitAuthLockoutsTotal.WithLabelValues(lockoutType).Inc()
}

// SetLockedIdentifiers sets the gauge for currently locked identifiers.
func (m *Metrics) SetLockedIdentifiers(count int) {
	m.RateLimitAuthLockedIdentifiers.Set(float64(count))
}

// RecordQuotaUsage records quota usage for the given tier.
func (m *Metrics) RecordQuotaUsage(tier string) {
	m.QuotaUsageTotal.WithLabelValues(tier).Inc()
}

// RecordQuotaExceeded records a quota exceeded event for the given tier.
func (m *Metrics) RecordQuotaExceeded(tier string) {
	m.QuotaExceededTotal.WithLabelValues(tier).Inc()
}

// SetBucketEntries sets the gauge for active bucket entries.
func (m *Metrics) SetBucketEntries(count int) {
	m.BucketEntries.Set(float64(count))
}

// SetAllowlistEntries sets the gauge for allowlist entries of the given type.
func (m *Metrics) SetAllowlistEntries(entryType string, count int) {
	m.AllowlistEntries.WithLabelValues(entryType).Set(float64(count))
}

// SetAuthLockoutRecords sets the gauge for auth lockout records.
func (m *Metrics) SetAuthLockoutRecords(count int) {
	m.AuthLockoutRecords.Set(float64(count))
}

// IncrementCleanupFailuresReset increments the cleanup failures reset counter.
func (m *Metrics) IncrementCleanupFailuresReset(count int) {
	m.RateLimitCleanupFailuresResetTotal.Add(float64(count))
}

// IncrementCleanupDailyFailuresReset increments the cleanup daily failures reset counter.
func (m *Metrics) IncrementCleanupDailyFailuresReset(count int) {
	m.RateLimitCleanupDailyFailuresResetTotal.Add(float64(count))
}

// IncrementCleanupRuns increments the cleanup runs counter with the given status.
func (m *Metrics) IncrementCleanupRuns(status string) {
	m.RateLimitCleanupRunsTotal.WithLabelValues(status).Inc()
}

// ObserveCleanupDuration records the duration of a cleanup run.
func (m *Metrics) ObserveCleanupDuration(durationSeconds float64) {
	m.RateLimitCleanupDurationSeconds.Observe(durationSeconds)
}

// RecordCleanupEntriesRemoved records entries removed during cleanup.
func (m *Metrics) RecordCleanupEntriesRemoved(entryType string, count int) {
	m.CleanupEntriesRemovedTotal.WithLabelValues(entryType).Add(float64(count))
}
