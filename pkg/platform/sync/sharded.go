package sync

import (
	"sync"
)

// ShardedMutex provides fine-grained locking using sharded mutexes.
// Instead of a single global lock, operations are distributed across N shards
// based on a hash of the resource key, reducing contention under concurrent load.
type ShardedMutex struct {
	shards [32]sync.Mutex
}

// NewShardedMutex creates a new ShardedMutex with 32 shards.
func NewShardedMutex() *ShardedMutex {
	return &ShardedMutex{}
}

// Lock acquires the lock for the given key's shard.
// Empty keys default to shard 0.
func (m *ShardedMutex) Lock(key string) {
	shard := m.shardFor(key)
	m.shards[shard].Lock()
}

// Unlock releases the lock for the given key's shard.
// Empty keys default to shard 0.
func (m *ShardedMutex) Unlock(key string) {
	shard := m.shardFor(key)
	m.shards[shard].Unlock()
}

// shardFor returns the shard index for the given key.
func (m *ShardedMutex) shardFor(key string) int {
	if key == "" {
		return 0
	}
	return int(hashString(key) % uint32(len(m.shards)))
}

// hashString provides a simple hash for shard selection.
// Uses djb2-style hashing for good distribution.
func hashString(s string) uint32 {
	var h uint32
	for i := 0; i < len(s); i++ {
		h = h*31 + uint32(s[i])
	}
	return h
}
