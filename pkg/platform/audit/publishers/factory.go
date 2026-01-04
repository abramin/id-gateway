// Package publishers provides the tri-publisher audit system.
//
// The audit system separates concerns into three publishers with different
// reliability guarantees:
//
//   - ComplianceAuditor: Synchronous, fail-closed for regulatory events
//   - SecurityAuditor: Async buffered with retry for security events
//   - OpsTracker: Fire-and-forget with sampling for operational events
package publishers

import (
	"log/slog"
	"time"

	audit "credo/pkg/platform/audit"
	"credo/pkg/platform/audit/publishers/compliance"
	"credo/pkg/platform/audit/publishers/ops"
	"credo/pkg/platform/audit/publishers/security"
)

// System holds all three publishers.
// Services inject only the publishers they need.
type System struct {
	Compliance *compliance.Publisher
	Security   *security.Publisher
	Ops        *ops.Publisher
}

// Config configures the audit system.
type Config struct {
	// Security publisher
	SecurityBufferSize   int
	SecurityFlushMs      int
	SecurityMaxRetries   int
	SecurityRetryBackoff time.Duration

	// Ops publisher
	OpsSampleRate        float64
	OpsCircuitThreshold  int
	OpsCircuitCooldownMs int
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		SecurityBufferSize:   10000,
		SecurityFlushMs:      50,
		SecurityMaxRetries:   3,
		SecurityRetryBackoff: 100 * time.Millisecond,
		OpsSampleRate:        0.1, // 10%
		OpsCircuitThreshold:  5,
		OpsCircuitCooldownMs: 60000, // 1 minute
	}
}

// New creates the tri-publisher audit system.
// All publishers share the same underlying store (outbox-backed in production).
func New(store audit.Store, cfg Config, logger *slog.Logger) *System {
	s := &System{}

	// Compliance: synchronous, fail-closed
	complianceMetrics := compliance.NewMetrics()
	s.Compliance = compliance.New(store,
		compliance.WithLogger(logger),
		compliance.WithMetrics(complianceMetrics),
	)

	// Security: async buffered with retry
	securityMetrics := security.NewMetrics()
	s.Security = security.New(store,
		security.WithLogger(logger),
		security.WithMetrics(securityMetrics),
		security.WithBufferSize(cfg.SecurityBufferSize),
		security.WithFlushInterval(time.Duration(cfg.SecurityFlushMs)*time.Millisecond),
		security.WithMaxRetries(cfg.SecurityMaxRetries),
		security.WithRetryBackoff(cfg.SecurityRetryBackoff),
	)

	// Ops: fire-and-forget with sampling
	opsMetrics := ops.NewMetrics()
	s.Ops = ops.New(store,
		ops.WithLogger(logger),
		ops.WithMetrics(opsMetrics),
		ops.WithSampleRate(cfg.OpsSampleRate),
		ops.WithCircuitThreshold(cfg.OpsCircuitThreshold),
		ops.WithCircuitCooldown(time.Duration(cfg.OpsCircuitCooldownMs)*time.Millisecond),
	)

	return s
}

// Close shuts down all publishers gracefully.
func (s *System) Close() error {
	// Security publisher needs graceful drain
	if s.Security != nil {
		if err := s.Security.Close(); err != nil {
			return err
		}
	}

	// Others are no-ops
	if s.Compliance != nil {
		_ = s.Compliance.Close() //nolint:errcheck // best-effort cleanup
	}
	if s.Ops != nil {
		_ = s.Ops.Close() //nolint:errcheck // best-effort cleanup
	}

	return nil
}
