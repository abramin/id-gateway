package revocation

import (
	"context"
	"sync"
	"time"
)

// InMemoryTRL is an in-memory implementation of TokenRevocationList for MVP/testing.
// For production, use RedisTRL for distributed token revocation.
type InMemoryTRL struct {
	mu              sync.RWMutex
	revoked         map[string]time.Time // jti -> expiry timestamp
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

// NewInMemoryTRL creates a new in-memory token revocation list.
func NewInMemoryTRL(opts ...InMemoryTRLOption) *InMemoryTRL {
	trl := &InMemoryTRL{
		revoked:         make(map[string]time.Time),
		cleanupInterval: 1 * time.Minute, // Reduced from 5min for bounded memory growth
		stopCh:          make(chan struct{}),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(trl)
		}
	}
	// Start cleanup goroutine to remove expired entries
	go trl.cleanup()
	return trl
}

// Close stops the cleanup goroutine.
func (t *InMemoryTRL) Close() {
	close(t.stopCh)
}

// RevokeToken adds a token to the revocation list with TTL.
func (t *InMemoryTRL) RevokeToken(ctx context.Context, jti string, ttl time.Duration) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.revoked[jti] = time.Now().Add(ttl)
	return nil
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
func (t *InMemoryTRL) RevokeSessionTokens(ctx context.Context, sessionID string, jtis []string, ttl time.Duration) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	expiry := time.Now().Add(ttl)
	for _, jti := range jtis {
		t.revoked[jti] = expiry
	}
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
			t.mu.Unlock()
		}
	}
}
