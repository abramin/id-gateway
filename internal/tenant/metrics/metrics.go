package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Metrics struct {
	TenantCreated prometheus.Counter
}

func New() *Metrics {
	return &Metrics{
		TenantCreated: promauto.NewCounter(prometheus.CounterOpts{
			Name: "credo_tenants_created_total",
			Help: "Total number of tenants created",
		}),
	}
}

func (m *Metrics) IncrementTenantCreated() {
	m.TenantCreated.Inc()
}
