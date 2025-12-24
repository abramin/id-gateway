package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Metrics struct {
	TenantCreated         prometheus.Counter
	ResolveClientDuration prometheus.Histogram
}

func New() *Metrics {
	return &Metrics{
		TenantCreated: promauto.NewCounter(prometheus.CounterOpts{
			Name: "credo_tenants_created_total",
			Help: "Total number of tenants created",
		}),
		ResolveClientDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "credo_resolve_client_duration_seconds",
			Help:    "Duration of ResolveClient operations (OAuth critical path)",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
		}),
	}
}

func (m *Metrics) IncrementTenantCreated() {
	m.TenantCreated.Inc()
}

func (m *Metrics) ObserveResolveClient(start time.Time) {
	m.ResolveClientDuration.Observe(time.Since(start).Seconds())
}
