package revocation

import (
	"context"
	"sync"
	"time"
)

// DefaultMaxSize is the default maximum number of entries in the TRL.
const DefaultMaxSize = 10000

// InMemoryTRL is an in-memory implementation of TokenRevocationList for MVP/testing.
// For production, use RedisTRL for distributed token revocation.
type InMemoryTRL struct {
	mu              sync.RWMutex
	revoked         map[string]time.Time // jti -> expiry timestamp
	order           []string             // FIFO order for eviction
	maxSize         int                  // max entries before eviction (0 = unlimited)
	cleanupInterval time.Duration
	stopCh          chan struct{}
}

type InMemoryTRLOption func(*InMemoryTRL)

func WithCleanupInterval(d time.Duration) InMemoryTRLOption {
	return func(trl *InMemoryTRL) {
		if d > 0 {
			trl.cleanupInterval = d
		}
	}
}

// WithMaxSize sets the maximum number of entries before FIFO eviction.
// A value of 0 means unlimited (no eviction).
func WithMaxSize(maxSize int) InMemoryTRLOption {
	return func(trl *InMemoryTRL) {
		if maxSize >= 0 {
			trl.maxSize = maxSize
		}
	}
}

func NewInMemoryTRL(opts ...InMemoryTRLOption) *InMemoryTRL {
	trl := &InMemoryTRL{
		revoked:         make(map[string]time.Time),
		order:           make([]string, 0),
		maxSize:         DefaultMaxSize,
		cleanupInterval: 1 * time.Minute,
		stopCh:          make(chan struct{}),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(trl)
		}
	}
	go trl.cleanup()
	return trl
}

func (t *InMemoryTRL) Close() {
	close(t.stopCh)
}

// RevokeToken adds a token to the revocation list with TTL.
// If maxSize is exceeded, oldest entries are evicted (FIFO).
func (t *InMemoryTRL) RevokeToken(ctx context.Context, jti string, ttl time.Duration) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Check if already revoked (update expiry, don't add to order again)
	if _, exists := t.revoked[jti]; exists {
		t.revoked[jti] = time.Now().Add(ttl)
		return nil
	}

	// Evict oldest entries if at capacity
	t.evictIfNeeded(1)

	t.revoked[jti] = time.Now().Add(ttl)
	t.order = append(t.order, jti)
	return nil
}

// evictIfNeeded removes oldest entries to make room for n new entries.
// Must be called with lock held.
func (t *InMemoryTRL) evictIfNeeded(n int) {
	if t.maxSize == 0 {
		return // unlimited
	}
	for len(t.revoked)+n > t.maxSize && len(t.order) > 0 {
		oldest := t.order[0]
		t.order = t.order[1:]
		delete(t.revoked, oldest)
	}
}

// IsRevoked checks if a token is in the revocation list.
func (t *InMemoryTRL) IsRevoked(ctx context.Context, jti string) (bool, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	expiry, exists := t.revoked[jti]
	if !exists {
		return false, nil
	}

	// Check if the revocation has expired (token would have expired anyway)
	if time.Now().After(expiry) {
		return false, nil
	}

	return true, nil
}

// RevokeSessionTokens revokes multiple tokens associated with a session.
// If maxSize is exceeded, oldest entries are evicted (FIFO).
func (t *InMemoryTRL) RevokeSessionTokens(ctx context.Context, sessionID string, jtis []string, ttl time.Duration) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Identify truly new JTIs and update existing ones
	expiry := time.Now().Add(ttl)
	newJTIs := make([]string, 0, len(jtis))
	for _, jti := range jtis {
		if _, exists := t.revoked[jti]; !exists {
			newJTIs = append(newJTIs, jti)
		} else {
			// Update expiry for existing entries
			t.revoked[jti] = expiry
		}
	}

	// Evict oldest entries before adding new ones
	t.evictIfNeeded(len(newJTIs))

	// Add new entries
	for _, jti := range newJTIs {
		t.revoked[jti] = expiry
	}
	t.order = append(t.order, newJTIs...)
	return nil
}

// cleanup periodically removes expired entries from the revocation list.
func (t *InMemoryTRL) cleanup() {
	ticker := time.NewTicker(t.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			t.mu.Lock()
			now := time.Now()
			for jti, expiry := range t.revoked {
				if now.After(expiry) {
					delete(t.revoked, jti)
				}
			}
			// Compact order slice to only contain JTIs still in the map
			t.compactOrder()
			t.mu.Unlock()
		}
	}
}

// compactOrder removes JTIs from the order slice that are no longer in the map.
// Must be called with lock held.
func (t *InMemoryTRL) compactOrder() {
	if len(t.order) == 0 {
		return
	}
	newOrder := make([]string, 0, len(t.revoked))
	for _, jti := range t.order {
		if _, exists := t.revoked[jti]; exists {
			newOrder = append(newOrder, jti)
		}
	}
	t.order = newOrder
}
