package redis

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/redis/go-redis/v9"

	"credo/internal/platform/config"
)

var (
	redisPoolHits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "credo_redis_pool_hits_total",
		Help: "Number of times a connection was found in the pool",
	})
	redisPoolMisses = promauto.NewCounter(prometheus.CounterOpts{
		Name: "credo_redis_pool_misses_total",
		Help: "Number of times a connection was not found in the pool",
	})
	redisPoolTimeouts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "credo_redis_pool_timeouts_total",
		Help: "Number of times a connection was not obtained due to timeout",
	})
	redisPoolTotalConns = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "credo_redis_pool_total_conns",
		Help: "Number of total connections in the pool",
	})
	redisPoolIdleConns = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "credo_redis_pool_idle_conns",
		Help: "Number of idle connections in the pool",
	})
	redisPoolStaleConns = promauto.NewCounter(prometheus.CounterOpts{
		Name: "credo_redis_pool_stale_conns_total",
		Help: "Number of stale connections removed from the pool",
	})
)

// Client wraps the go-redis client with health checking capabilities.
type Client struct {
	*redis.Client
	lastStats *redis.PoolStats
}

// New creates a new Redis client from the provided configuration.
// Returns nil if the URL is empty (Redis not configured).
func New(cfg config.RedisConfig) (*Client, error) {
	if cfg.URL == "" {
		return nil, nil
	}

	opts, err := redis.ParseURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("parse redis URL: %w", err)
	}

	// Apply configuration overrides
	opts.PoolSize = cfg.PoolSize
	opts.MinIdleConns = cfg.MinIdleConns
	opts.DialTimeout = cfg.DialTimeout
	opts.ReadTimeout = cfg.ReadTimeout
	opts.WriteTimeout = cfg.WriteTimeout

	client := redis.NewClient(opts)

	// Test connection
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		client.Close() //nolint:errcheck // best-effort cleanup on init failure
		return nil, fmt.Errorf("redis ping failed: %w", err)
	}

	return &Client{Client: client}, nil
}

// Health checks if the Redis connection is healthy.
func (c *Client) Health(ctx context.Context) error {
	return c.Ping(ctx).Err()
}

// Close closes the Redis connection.
func (c *Client) Close() error {
	return c.Client.Close()
}

// RecordPoolStats updates Prometheus metrics with current pool statistics.
// Call this periodically (e.g., every 15 seconds) from a background goroutine.
func (c *Client) RecordPoolStats() {
	stats := c.PoolStats()

	// Update gauge metrics (current values)
	redisPoolTotalConns.Set(float64(stats.TotalConns))
	redisPoolIdleConns.Set(float64(stats.IdleConns))

	// Update counter metrics (delta from last recorded)
	if c.lastStats != nil {
		if stats.Hits > c.lastStats.Hits {
			redisPoolHits.Add(float64(stats.Hits - c.lastStats.Hits))
		}
		if stats.Misses > c.lastStats.Misses {
			redisPoolMisses.Add(float64(stats.Misses - c.lastStats.Misses))
		}
		if stats.Timeouts > c.lastStats.Timeouts {
			redisPoolTimeouts.Add(float64(stats.Timeouts - c.lastStats.Timeouts))
		}
		if stats.StaleConns > c.lastStats.StaleConns {
			redisPoolStaleConns.Add(float64(stats.StaleConns - c.lastStats.StaleConns))
		}
	} else {
		// First call: record initial values
		redisPoolHits.Add(float64(stats.Hits))
		redisPoolMisses.Add(float64(stats.Misses))
		redisPoolTimeouts.Add(float64(stats.Timeouts))
		redisPoolStaleConns.Add(float64(stats.StaleConns))
	}

	c.lastStats = stats
}
