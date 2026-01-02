package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"credo/internal/evidence/registry/metrics"
	"credo/internal/evidence/registry/models"
	id "credo/pkg/domain"

	"github.com/redis/go-redis/v9"
)

const (
	redisCitizenKeyPrefix  = "registry:citizen:"
	redisSanctionKeyPrefix = "registry:sanction:"
)

// RedisCache persists registry cache entries in Redis with TTL-based eviction.
type RedisCache struct {
	client   *redis.Client
	cacheTTL time.Duration
	metrics  *metrics.Metrics
}

// NewRedisCache constructs a Redis-backed registry cache.
// Usage: pass a configured Redis client; metrics may be nil.
func NewRedisCache(client *redis.Client, cacheTTL time.Duration, metrics *metrics.Metrics) *RedisCache {
	return &RedisCache{
		client:   client,
		cacheTTL: cacheTTL,
		metrics:  metrics,
	}
}

// FindCitizen loads a cached citizen record by national ID and regulation mode.
//
// Side effects: performs a Redis GET and records cache hit/miss metrics.
//
// Errors: returns ErrNotFound on cache miss; wraps Redis or JSON decode errors.
func (c *RedisCache) FindCitizen(ctx context.Context, nationalID id.NationalID, regulated bool) (*models.CitizenRecord, error) {
	start := time.Now()
	key := citizenKey(nationalID, regulated)
	data, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			c.recordMiss("citizen", start)
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("find citizen cache: %w", err)
	}

	var record models.CitizenRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("decode citizen cache: %w", err)
	}
	c.recordHit("citizen", start)
	return &record, nil
}

// SaveCitizen writes a citizen record to Redis with TTL eviction.
//
// Side effects: performs a Redis SET; overwrites any existing entry.
//
// Errors: returns an error if the record is nil, cannot be encoded, or the write fails.
func (c *RedisCache) SaveCitizen(ctx context.Context, key id.NationalID, record *models.CitizenRecord, regulated bool) error {
	if record == nil {
		return fmt.Errorf("citizen record is required")
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode citizen cache: %w", err)
	}
	if err := c.client.Set(ctx, citizenKey(key, regulated), payload, c.cacheTTL).Err(); err != nil {
		return fmt.Errorf("save citizen cache: %w", err)
	}
	return nil
}

// FindSanction loads a cached sanctions record by national ID.
//
// Side effects: performs a Redis GET and records cache hit/miss metrics.
//
// Errors: returns ErrNotFound on cache miss; wraps Redis or JSON decode errors.
func (c *RedisCache) FindSanction(ctx context.Context, nationalID id.NationalID) (*models.SanctionsRecord, error) {
	start := time.Now()
	key := sanctionKey(nationalID)
	data, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			c.recordMiss("sanctions", start)
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("find sanctions cache: %w", err)
	}

	var record models.SanctionsRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("decode sanctions cache: %w", err)
	}
	c.recordHit("sanctions", start)
	return &record, nil
}

// SaveSanction writes a sanctions record to Redis with TTL eviction.
//
// Side effects: performs a Redis SET; overwrites any existing entry.
//
// Errors: returns an error if the record is nil, cannot be encoded, or the write fails.
func (c *RedisCache) SaveSanction(ctx context.Context, key id.NationalID, record *models.SanctionsRecord) error {
	if record == nil {
		return fmt.Errorf("sanctions record is required")
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode sanctions cache: %w", err)
	}
	if err := c.client.Set(ctx, sanctionKey(key), payload, c.cacheTTL).Err(); err != nil {
		return fmt.Errorf("save sanctions cache: %w", err)
	}
	return nil
}

// recordHit emits cache hit metrics for the given record type.
func (c *RedisCache) recordHit(recordType string, start time.Time) {
	if c.metrics == nil {
		return
	}
	c.metrics.RecordCacheHit(recordType)
	c.metrics.ObserveLookupDuration(recordType, time.Since(start).Seconds())
}

// recordMiss emits cache miss metrics for the given record type.
func (c *RedisCache) recordMiss(recordType string, start time.Time) {
	if c.metrics == nil {
		return
	}
	c.metrics.RecordCacheMiss(recordType)
	c.metrics.ObserveLookupDuration(recordType, time.Since(start).Seconds())
}

func citizenKey(nationalID id.NationalID, regulated bool) string {
	return fmt.Sprintf("%s%s:%t", redisCitizenKeyPrefix, nationalID.String(), regulated)
}

func sanctionKey(nationalID id.NationalID) string {
	return fmt.Sprintf("%s%s", redisSanctionKeyPrefix, nationalID.String())
}
