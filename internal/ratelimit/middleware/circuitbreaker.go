package middleware

import "sync"

// CircuitBreaker tracks consecutive limiter errors for fail-safe rate limiting (PRD-017 FR-7):
// - Track consecutive limiter errors.
// - Open circuit after N failures; during open, use the configured fallback limiter.
// - When open, set X-RateLimit-Status: degraded so callers know they're in fallback mode.
// - Close circuit after M consecutive successful primary checks.
type CircuitBreaker struct {
	mu               sync.Mutex
	name             string // identifier for logging (e.g., "ip", "combined", "client")
	state            circuitState
	failureCount     int
	successCount     int
	failureThreshold int
	successThreshold int
}

type circuitState int

const (
	circuitClosed circuitState = iota
	circuitOpen
)

// StateChange represents a circuit breaker state transition for observability.
type StateChange struct {
	Opened bool // circuit just opened (threshold reached)
	Closed bool // circuit just closed (recovery complete)
}

func newCircuitBreaker(name string) *CircuitBreaker {
	return &CircuitBreaker{
		name:             name,
		state:            circuitClosed,
		failureThreshold: 5,
		successThreshold: 3,
	}
}

func (c *CircuitBreaker) IsOpen() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state == circuitOpen
}

// RecordFailure records a failed check. Returns:
// - useFallback: true if fallback should be used (circuit is open)
// - change: state transition info for logging
func (c *CircuitBreaker) RecordFailure() (useFallback bool, change StateChange) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failureCount++
	c.successCount = 0
	if c.state == circuitOpen {
		return true, StateChange{}
	}
	if c.failureCount >= c.failureThreshold {
		c.state = circuitOpen
		return true, StateChange{Opened: true}
	}
	return false, StateChange{}
}

// RecordSuccess records a successful check. Returns:
// - usePrimary: true if primary should be used (circuit is closed or just recovered)
// - change: state transition info for logging
func (c *CircuitBreaker) RecordSuccess() (usePrimary bool, change StateChange) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == circuitOpen {
		c.successCount++
		if c.successCount >= c.successThreshold {
			c.state = circuitClosed
			c.failureCount = 0
			c.successCount = 0
			return true, StateChange{Closed: true}
		}
		return false, StateChange{}
	}
	c.failureCount = 0
	return true, StateChange{}
}

// ShouldUsePrimary returns true if the circuit is closed and primary limiter should be used.
// This is an alias for checking circuit state without recording success/failure.
func (c *CircuitBreaker) ShouldUsePrimary() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state == circuitClosed
}

// Name returns the circuit breaker identifier for logging.
func (c *CircuitBreaker) Name() string {
	return c.name
}
