package sync

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShardedMutex_LockUnlock(t *testing.T) {
	m := NewShardedMutex()

	// Basic lock/unlock should not deadlock
	m.Lock("key1")
	m.Unlock("key1")

	// Empty key should work (defaults to shard 0)
	m.Lock("")
	m.Unlock("")
}

func TestShardedMutex_DifferentKeysNoContention(t *testing.T) {
	m := NewShardedMutex()

	// Different keys can be locked concurrently if they hash to different shards
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(key string) {
			defer wg.Done()
			m.Lock(key)
			defer m.Unlock(key)
		}("key" + string(rune('A'+i%26)))
	}
	wg.Wait()
}

func TestShardedMutex_SameKeySerializes(t *testing.T) {
	m := NewShardedMutex()
	counter := 0
	var wg sync.WaitGroup

	// Same key should serialize access
	for range 100 {
		wg.Go(func() {
			m.Lock("same-key")
			defer m.Unlock("same-key")
			counter++
		})
	}
	wg.Wait()

	assert.Equal(t, 100, counter)
}

func TestShardedMutex_ShardDistribution(t *testing.T) {
	m := NewShardedMutex()

	// Verify different keys map to different shards (probabilistically)
	shards := make(map[int]bool)
	keys := []string{"user-123", "user-456", "session-abc", "session-xyz", "token-1", "token-2"}

	for _, key := range keys {
		shards[m.shardFor(key)] = true
	}

	// With 6 diverse keys and 32 shards, we should hit at least 3 different shards
	assert.GreaterOrEqual(t, len(shards), 3, "expected keys to distribute across multiple shards")
}

func TestHashString(t *testing.T) {
	// Same string should produce same hash
	assert.Equal(t, hashString("test"), hashString("test"))

	// Different strings should (usually) produce different hashes
	assert.NotEqual(t, hashString("test1"), hashString("test2"))

	// Empty string should produce 0
	assert.Equal(t, uint32(0), hashString(""))
}
