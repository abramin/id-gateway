package adapters

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"credo/internal/tenant/models"
)

// ClientResolver resolves client metadata and tenant ownership.
type ClientResolver interface {
	ResolveClient(ctx context.Context, clientID string) (*models.Client, *models.Tenant, error)
}

// ResilientClientResolver wraps a ClientResolver with circuit breaker protection.
// When the circuit opens (after consecutive failures), it returns cached
// client data if available, preventing cascade failures.
type ResilientClientResolver struct {
	delegate ClientResolver
	cb       *circuitBreaker
	cache    *clientCache
	logger   *slog.Logger
}

// ResilientClientResolverOption configures the resilient resolver.
type ResilientClientResolverOption func(*ResilientClientResolver)

// WithFailureThreshold sets the number of consecutive failures to open the circuit.
func WithFailureThreshold(n int) ResilientClientResolverOption {
	return func(r *ResilientClientResolver) {
		r.cb.failureThreshold = n
	}
}

// WithSuccessThreshold sets the number of consecutive successes to close the circuit.
func WithSuccessThreshold(n int) ResilientClientResolverOption {
	return func(r *ResilientClientResolver) {
		r.cb.successThreshold = n
	}
}

// WithCacheTTL sets the cache TTL for client data.
func WithCacheTTL(ttl time.Duration) ResilientClientResolverOption {
	return func(r *ResilientClientResolver) {
		r.cache = newClientCache(ttl)
	}
}

// NewResilientClientResolver creates a circuit-breaker-protected client resolver.
func NewResilientClientResolver(
	delegate ClientResolver,
	logger *slog.Logger,
	opts ...ResilientClientResolverOption,
) *ResilientClientResolver {
	r := &ResilientClientResolver{
		delegate: delegate,
		cb:       newCircuitBreaker("client_resolver"),
		cache:    newClientCache(5 * time.Minute), // default 5 min TTL
		logger:   logger,
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

// ResolveClient resolves a client with circuit breaker protection.
// On success: caches the result and records success.
// On failure: records failure, returns cached data if circuit is open.
func (r *ResilientClientResolver) ResolveClient(ctx context.Context, clientID string) (*models.Client, *models.Tenant, error) {
	// If circuit is open, try cache first
	if r.cb.IsOpen() {
		if client, tenant, ok := r.cache.Get(clientID); ok {
			r.logger.WarnContext(ctx, "circuit open, using cached client",
				"client_id", clientID,
				"circuit", r.cb.Name(),
			)
			return client, tenant, nil
		}
		// No cache hit and circuit open - still try delegate (half-open behavior)
	}

	// Try delegate
	client, tenant, err := r.delegate.ResolveClient(ctx, clientID)
	if err != nil {
		useFallback, change := r.cb.RecordFailure()
		if change.Opened {
			r.logger.ErrorContext(ctx, "circuit breaker opened",
				"circuit", r.cb.Name(),
				"error", err,
			)
		}

		// If circuit is open and we have cached data, use it
		if useFallback {
			if cachedClient, cachedTenant, ok := r.cache.Get(clientID); ok {
				r.logger.WarnContext(ctx, "using cached client after failure",
					"client_id", clientID,
					"circuit", r.cb.Name(),
				)
				return cachedClient, cachedTenant, nil
			}
		}

		return nil, nil, err
	}

	// Success: record and cache
	_, change := r.cb.RecordSuccess()
	if change.Closed {
		r.logger.InfoContext(ctx, "circuit breaker closed",
			"circuit", r.cb.Name(),
		)
	}

	r.cache.Set(clientID, client, tenant)
	return client, tenant, nil
}

// circuitBreaker tracks consecutive failures for fail-safe client resolution.
type circuitBreaker struct {
	mu               sync.Mutex
	name             string
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

// stateChange represents a circuit breaker state transition.
type stateChange struct {
	Opened bool
	Closed bool
}

func newCircuitBreaker(name string) *circuitBreaker {
	return &circuitBreaker{
		name:             name,
		state:            circuitClosed,
		failureThreshold: 5,
		successThreshold: 3,
	}
}

func (c *circuitBreaker) IsOpen() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state == circuitOpen
}

func (c *circuitBreaker) RecordFailure() (useFallback bool, change stateChange) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failureCount++
	c.successCount = 0
	if c.state == circuitOpen {
		return true, stateChange{}
	}
	if c.failureCount >= c.failureThreshold {
		c.state = circuitOpen
		return true, stateChange{Opened: true}
	}
	return false, stateChange{}
}

func (c *circuitBreaker) RecordSuccess() (usePrimary bool, change stateChange) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == circuitOpen {
		c.successCount++
		if c.successCount >= c.successThreshold {
			c.state = circuitClosed
			c.failureCount = 0
			c.successCount = 0
			return true, stateChange{Closed: true}
		}
		return false, stateChange{}
	}
	c.failureCount = 0
	return true, stateChange{}
}

func (c *circuitBreaker) Name() string {
	return c.name
}

// Ensure ResilientClientResolver implements the interface expected by auth service.
var _ interface {
	ResolveClient(ctx context.Context, clientID string) (*models.Client, *models.Tenant, error)
} = (*ResilientClientResolver)(nil)
