package revocation

import (
	"context"
	"sync"
	"time"
)

// TokenRevocationList manages revoked access tokens by JTI.
// Production systems should use Redis for distributed revocation.
type TokenRevocationList interface {
	// RevokeToken adds a token JTI to the revocation list with TTL
	RevokeToken(ctx context.Context, jti string, ttl time.Duration) error

	// IsRevoked checks if a token JTI is in the revocation list
	IsRevoked(ctx context.Context, jti string) (bool, error)

	// RevokeSessionTokens revokes multiple tokens for a session
	RevokeSessionTokens(ctx context.Context, sessionID string, jtis []string, ttl time.Duration) error
}

// InMemoryTRL is an in-memory implementation of TokenRevocationList for MVP/testing.
// For production, use RedisTRL for distributed token revocation.
type InMemoryTRL struct {
	mu      sync.RWMutex
	revoked map[string]time.Time // jti -> expiry timestamp
}

// NewInMemoryTRL creates a new in-memory token revocation list.
func NewInMemoryTRL() *InMemoryTRL {
	trl := &InMemoryTRL{
		revoked: make(map[string]time.Time),
	}
	// Start cleanup goroutine to remove expired entries
	go trl.cleanup()
	return trl
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
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
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
