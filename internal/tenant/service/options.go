package service

import (
	"log/slog"

	tenantmetrics "credo/internal/tenant/metrics"
)

// serviceConfig holds optional dependencies for services.
type serviceConfig struct {
	logger         *slog.Logger
	auditPublisher AuditPublisher
	metrics        *tenantmetrics.Metrics
}

// Option configures a service.
type Option func(c *serviceConfig)

func WithLogger(logger *slog.Logger) Option {
	return func(c *serviceConfig) {
		c.logger = logger
	}
}

func WithAuditPublisher(publisher AuditPublisher) Option {
	return func(c *serviceConfig) {
		c.auditPublisher = publisher
	}
}

func WithMetrics(m *tenantmetrics.Metrics) Option {
	return func(c *serviceConfig) {
		c.metrics = m
	}
}
