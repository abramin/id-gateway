package consumer

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

// Message represents a received Kafka message.
type Message struct {
	Topic     string
	Partition int32
	Offset    int64
	Key       []byte
	Value     []byte
	Headers   map[string]string
	Timestamp time.Time
}

// Handler processes consumed messages.
type Handler interface {
	// Handle processes a message. Return error to skip commit (message will be redelivered).
	Handle(ctx context.Context, msg *Message) error
}

// Consumer wraps the franz-go client for consuming messages.
type Consumer struct {
	client  *kgo.Client
	handler Handler
	logger  *slog.Logger
	topics  []string

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.RWMutex
	closed bool
}

// Config holds consumer configuration.
type Config struct {
	Brokers         string
	GroupID         string
	AutoOffsetReset string
}

// New creates a new Kafka consumer.
func New(cfg Config, handler Handler, logger *slog.Logger) (*Consumer, error) {
	if cfg.Brokers == "" {
		return nil, fmt.Errorf("kafka brokers not configured")
	}

	if cfg.GroupID == "" {
		return nil, fmt.Errorf("kafka consumer group ID not configured")
	}

	brokers := strings.Split(cfg.Brokers, ",")

	// Map auto offset reset
	var resetOffset kgo.Offset
	switch cfg.AutoOffsetReset {
	case "latest":
		resetOffset = kgo.NewOffset().AtEnd()
	default:
		resetOffset = kgo.NewOffset().AtStart()
	}

	opts := []kgo.Opt{
		kgo.SeedBrokers(brokers...),
		kgo.ConsumerGroup(cfg.GroupID),
		kgo.ConsumeResetOffset(resetOffset),
		kgo.DisableAutoCommit(), // Manual commits for at-least-once delivery
	}

	client, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("create kafka consumer: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Consumer{
		client:  client,
		handler: handler,
		logger:  logger,
		ctx:     ctx,
		cancel:  cancel,
	}, nil
}

// Subscribe starts consuming from the specified topics.
func (c *Consumer) Subscribe(topics []string) error {
	c.mu.Lock()
	c.topics = topics
	c.mu.Unlock()

	c.client.AddConsumeTopics(topics...)
	return nil
}

// Start begins the consumption loop in a background goroutine.
func (c *Consumer) Start() {
	c.wg.Add(1)
	go c.run()
}

// run is the main consumption loop.
func (c *Consumer) run() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			c.poll()
		}
	}
}

// poll reads and processes messages.
func (c *Consumer) poll() {
	fetches := c.client.PollFetches(c.ctx)
	if fetches.IsClientClosed() {
		return
	}

	// Log any errors
	fetches.EachError(func(topic string, partition int32, err error) {
		if c.logger != nil {
			c.logger.Error("kafka consumer error",
				"topic", topic,
				"partition", partition,
				"error", err,
			)
		}
	})

	// Process records
	fetches.EachRecord(func(record *kgo.Record) {
		c.handleRecord(record)
	})
}

// handleRecord processes a single Kafka record.
func (c *Consumer) handleRecord(record *kgo.Record) {
	// Convert headers
	headers := make(map[string]string)
	for _, h := range record.Headers {
		headers[h.Key] = string(h.Value)
	}

	msg := &Message{
		Topic:     record.Topic,
		Partition: record.Partition,
		Offset:    record.Offset,
		Key:       record.Key,
		Value:     record.Value,
		Headers:   headers,
		Timestamp: record.Timestamp,
	}

	// Process message
	if err := c.handler.Handle(c.ctx, msg); err != nil {
		if c.logger != nil {
			c.logger.Error("failed to handle message",
				"topic", msg.Topic,
				"partition", msg.Partition,
				"offset", msg.Offset,
				"error", err,
			)
		}
		// Don't commit - message will be redelivered
		return
	}

	// Commit offset
	if err := c.client.CommitRecords(c.ctx, record); err != nil {
		if c.logger != nil {
			c.logger.Error("failed to commit offset",
				"topic", msg.Topic,
				"partition", msg.Partition,
				"offset", msg.Offset,
				"error", err,
			)
		}
	}
}

// Stop gracefully stops the consumer.
func (c *Consumer) Stop(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	c.cancel()

	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		c.client.Close()
		return nil
	case <-ctx.Done():
		c.client.Close()
		return ctx.Err()
	}
}

// Healthy checks if the consumer is connected.
func (c *Consumer) Healthy(ctx context.Context) bool {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return false
	}
	c.mu.RUnlock()

	// Ping the brokers to check connectivity
	if err := c.client.Ping(ctx); err != nil {
		return false
	}
	return true
}
