// Package circuit provides a simple circuit breaker implementation for resilience.
package circuit

import "sync"

// State represents the circuit breaker state.
type State int

const (
	// StateClosed means the circuit is healthy and requests flow normally.
	StateClosed State = iota
	// StateOpen means the circuit has tripped and requests should use fallback.
	StateOpen
)

// StateChange represents a circuit breaker state transition.
type StateChange struct {
	Opened bool
	Closed bool
}

// Breaker tracks consecutive failures for fail-safe operations.
// It implements a simple two-state circuit breaker (closed/open).
// When closed, requests flow normally. After FailureThreshold consecutive
// failures, the circuit opens. After SuccessThreshold consecutive successes
// while open, the circuit closes again.
type Breaker struct {
	mu               sync.Mutex
	state            State
	name             string
	failureCount     int
	successCount     int
	failureThreshold int
	successThreshold int
}

// Option configures a Breaker instance.
type Option func(*Breaker)

// WithFailureThreshold sets the number of consecutive failures to open the circuit.
// Default is 5.
func WithFailureThreshold(n int) Option {
	return func(b *Breaker) {
		if n > 0 {
			b.failureThreshold = n
		}
	}
}

// WithSuccessThreshold sets the number of consecutive successes to close the circuit.
// Default is 3.
func WithSuccessThreshold(n int) Option {
	return func(b *Breaker) {
		if n > 0 {
			b.successThreshold = n
		}
	}
}

// New creates a circuit breaker with the given name and options.
func New(name string, opts ...Option) *Breaker {
	b := &Breaker{
		name:             name,
		state:            StateClosed,
		failureThreshold: 5,
		successThreshold: 3,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(b)
		}
	}
	return b
}

// Name returns the circuit breaker's name for logging/metrics.
func (b *Breaker) Name() string {
	return b.name
}

// IsOpen returns true if the circuit is open (tripped).
func (b *Breaker) IsOpen() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state == StateOpen
}

// State returns the current circuit state.
func (b *Breaker) State() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

// RecordFailure records a failed operation.
// Returns (useFallback, stateChange):
//   - useFallback: true if the circuit is now open and callers should use fallback
//   - stateChange: indicates if the circuit just transitioned states
func (b *Breaker) RecordFailure() (useFallback bool, change StateChange) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.failureCount++
	b.successCount = 0

	if b.state == StateOpen {
		return true, StateChange{}
	}

	if b.failureCount >= b.failureThreshold {
		b.state = StateOpen
		return true, StateChange{Opened: true}
	}

	return false, StateChange{}
}

// RecordSuccess records a successful operation.
// Returns (usePrimary, stateChange):
//   - usePrimary: true if the caller should use the primary path
//   - stateChange: indicates if the circuit just transitioned states
func (b *Breaker) RecordSuccess() (usePrimary bool, change StateChange) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.state == StateOpen {
		b.successCount++
		if b.successCount >= b.successThreshold {
			b.state = StateClosed
			b.failureCount = 0
			b.successCount = 0
			return true, StateChange{Closed: true}
		}
		return false, StateChange{}
	}

	b.failureCount = 0
	return true, StateChange{}
}

// Reset resets the circuit breaker to closed state with zero counts.
func (b *Breaker) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.state = StateClosed
	b.failureCount = 0
	b.successCount = 0
}
