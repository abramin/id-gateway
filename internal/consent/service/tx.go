package service

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	pkgerrors "credo/pkg/domain-errors"
	platformsync "credo/pkg/platform/sync"
)

// Shard contention metrics for monitoring lock behavior
var (
	shardLockWaitDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "credo_consent_shard_lock_wait_seconds",
		Help:    "Time spent waiting to acquire shard lock",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
	})
	shardLockAcquisitions = promauto.NewCounter(prometheus.CounterOpts{
		Name: "credo_consent_shard_lock_acquisitions_total",
		Help: "Total number of shard lock acquisitions",
	})
)

// ConsentStoreTx provides a transactional boundary for consent store mutations.
// Implementations may wrap a database transaction or, in-memory, a coarse lock.
type ConsentStoreTx interface {
	RunInTx(ctx context.Context, fn func(store Store) error) error
}

// defaultConsentTxTimeout is the maximum duration for a consent transaction.
const defaultConsentTxTimeout = 5 * time.Second

type shardedConsentTx struct {
	mu      *platformsync.ShardedMutex
	store   Store
	timeout time.Duration
}

func (t *shardedConsentTx) RunInTx(ctx context.Context, fn func(store Store) error) error {
	// Check if context is already cancelled
	if err := ctx.Err(); err != nil {
		return pkgerrors.Wrap(err, pkgerrors.CodeTimeout, "transaction aborted: context cancelled")
	}

	// Apply timeout if not already set
	timeout := t.timeout
	if timeout == 0 {
		timeout = defaultConsentTxTimeout
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	key := t.shardKey(ctx)

	// Record lock acquisition timing for contention monitoring
	lockStart := time.Now()
	t.mu.Lock(key)
	shardLockWaitDuration.Observe(time.Since(lockStart).Seconds())
	shardLockAcquisitions.Inc()
	defer t.mu.Unlock(key)

	// Check again after acquiring lock
	if err := ctx.Err(); err != nil {
		return pkgerrors.Wrap(err, pkgerrors.CodeTimeout, "transaction aborted: context cancelled")
	}

	return fn(t.store)
}

// shardKey picks a shard based on user ID from context, or defaults to shard 0.
func (t *shardedConsentTx) shardKey(ctx context.Context) string {
	if userID, ok := ctx.Value(txUserKeyCtx).(string); ok && userID != "" {
		return userID
	}
	return ""
}

type txUserKey struct{}

var txUserKeyCtx = txUserKey{}
