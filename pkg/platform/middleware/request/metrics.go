package request

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Metrics struct {
	EndpointLatency *prometheus.HistogramVec
}

func NewMetrics() *Metrics {
	return &Metrics{
		EndpointLatency: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "credo_endpoint_latency_seconds",
			Help:    "Latency of endpoints in seconds",
			Buckets: prometheus.DefBuckets,
		}, []string{"endpoint"}),
	}
}

func (m *Metrics) ObserveEndpointLatency(endpoint string, durationSeconds float64) {
	m.EndpointLatency.WithLabelValues(endpoint).Observe(durationSeconds)
}
