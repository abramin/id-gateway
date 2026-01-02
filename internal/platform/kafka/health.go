package kafka

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// HealthChecker checks Kafka broker connectivity.
type HealthChecker struct {
	brokers string
	timeout time.Duration
}

// NewHealthChecker creates a new Kafka health checker.
func NewHealthChecker(brokers string) *HealthChecker {
	return &HealthChecker{
		brokers: brokers,
		timeout: 5 * time.Second,
	}
}

// Check verifies connectivity to Kafka brokers.
// Returns nil if at least one broker is reachable.
func (h *HealthChecker) Check(ctx context.Context) error {
	if h.brokers == "" {
		return fmt.Errorf("kafka brokers not configured")
	}

	brokerList := strings.Split(h.brokers, ",")
	var lastErr error

	for _, broker := range brokerList {
		broker = strings.TrimSpace(broker)
		if broker == "" {
			continue
		}

		// Try TCP connect with timeout
		dialer := net.Dialer{Timeout: h.timeout}
		conn, err := dialer.DialContext(ctx, "tcp", broker)
		if err != nil {
			lastErr = err
			continue
		}
		conn.Close()
		return nil // At least one broker is reachable
	}

	if lastErr != nil {
		return fmt.Errorf("no kafka brokers reachable: %w", lastErr)
	}

	return fmt.Errorf("no kafka brokers configured")
}

// Name returns the check name for health reporting.
func (h *HealthChecker) Name() string {
	return "kafka"
}
