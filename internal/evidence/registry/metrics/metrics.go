// Package metrics provides Prometheus metrics for the registry cache (PRD-003 PR-2).
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics contains all registry cache metrics as defined in PRD-003 PR-2.
type Metrics struct {
	// Cache operation metrics
	CacheHitsTotal   *prometheus.CounterVec // Cache hits by record type (citizen, sanctions)
	CacheMissesTotal *prometheus.CounterVec // Cache misses by record type (citizen, sanctions)

	// Latency metrics
	CacheLookupDurationSeconds *prometheus.HistogramVec // Cache lookup latency by record type

	// Cache state gauges
	CacheEntriesCitizen   prometheus.Gauge // Current number of citizen cache entries
	CacheEntriesSanctions prometheus.Gauge // Current number of sanctions cache entries

	// Cache invalidation metrics
	CacheInvalidationsTotal prometheus.Counter // Total cache clear operations
}

// New creates a new Metrics instance with all metrics registered.
func New() *Metrics {
	return &Metrics{
		CacheHitsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "credo_registry_cache_hits_total",
			Help: "Total number of registry cache hits by record type",
		}, []string{"type"}),

		CacheMissesTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "credo_registry_cache_misses_total",
			Help: "Total number of registry cache misses by record type",
		}, []string{"type"}),

		CacheLookupDurationSeconds: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "credo_registry_cache_lookup_duration_seconds",
			Help:    "Duration of cache lookup operations by record type",
			Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05}, // Focus on sub-5ms for cache hits
		}, []string{"type"}),

		CacheEntriesCitizen: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "credo_registry_cache_entries_citizen",
			Help: "Current number of citizen records in cache",
		}),

		CacheEntriesSanctions: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "credo_registry_cache_entries_sanctions",
			Help: "Current number of sanctions records in cache",
		}),

		CacheInvalidationsTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "credo_registry_cache_invalidations_total",
			Help: "Total number of cache clear (invalidation) operations",
		}),
	}
}

// RecordCacheHit records a cache hit for the given record type.
func (m *Metrics) RecordCacheHit(recordType string) {
	m.CacheHitsTotal.WithLabelValues(recordType).Inc()
}

// RecordCacheMiss records a cache miss for the given record type.
func (m *Metrics) RecordCacheMiss(recordType string) {
	m.CacheMissesTotal.WithLabelValues(recordType).Inc()
}

// ObserveLookupDuration records the duration of a cache lookup operation.
func (m *Metrics) ObserveLookupDuration(recordType string, durationSeconds float64) {
	m.CacheLookupDurationSeconds.WithLabelValues(recordType).Observe(durationSeconds)
}

// SetCacheEntries updates the cache entry gauges.
func (m *Metrics) SetCacheEntries(citizens, sanctions int) {
	m.CacheEntriesCitizen.Set(float64(citizens))
	m.CacheEntriesSanctions.Set(float64(sanctions))
}

// IncrementInvalidations records a cache invalidation event.
func (m *Metrics) IncrementInvalidations() {
	m.CacheInvalidationsTotal.Inc()
}

// CacheHitRate calculates the cache hit rate for a given record type.
// This is a helper for testing; in production, use Prometheus queries.
func CacheHitRate(hits, misses float64) float64 {
	total := hits + misses
	if total == 0 {
		return 0
	}
	return hits / total
}
