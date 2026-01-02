package consumer

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
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

// Consumer wraps the confluent-kafka-go consumer.
type Consumer struct {
	consumer *kafka.Consumer
	handler  Handler
	logger   *slog.Logger
	topics   []string

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

	autoOffsetReset := cfg.AutoOffsetReset
	if autoOffsetReset == "" {
		autoOffsetReset = "earliest"
	}

	configMap := &kafka.ConfigMap{
		"bootstrap.servers":  cfg.Brokers,
		"group.id":           cfg.GroupID,
		"auto.offset.reset":  autoOffsetReset,
		"enable.auto.commit": false, // Manual commits for at-least-once delivery
	}

	consumer, err := kafka.NewConsumer(configMap)
	if err != nil {
		return nil, fmt.Errorf("create kafka consumer: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Consumer{
		consumer: consumer,
		handler:  handler,
		logger:   logger,
		ctx:      ctx,
		cancel:   cancel,
	}, nil
}

// Subscribe starts consuming from the specified topics.
func (c *Consumer) Subscribe(topics []string) error {
	c.mu.Lock()
	c.topics = topics
	c.mu.Unlock()

	if err := c.consumer.SubscribeTopics(topics, nil); err != nil {
		return fmt.Errorf("subscribe to topics: %w", err)
	}

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

// poll reads and processes a single message.
func (c *Consumer) poll() {
	ev := c.consumer.Poll(100) // 100ms timeout
	if ev == nil {
		return
	}

	switch e := ev.(type) {
	case *kafka.Message:
		c.handleMessage(e)

	case kafka.Error:
		if e.Code() != kafka.ErrTimedOut {
			if c.logger != nil {
				c.logger.Error("kafka consumer error",
					"code", e.Code(),
					"error", e.Error(),
				)
			}
		}

	case kafka.PartitionEOF:
		// End of partition, normal operation
	}
}

// handleMessage processes a single Kafka message.
func (c *Consumer) handleMessage(km *kafka.Message) {
	// Convert headers
	headers := make(map[string]string)
	for _, h := range km.Headers {
		headers[h.Key] = string(h.Value)
	}

	msg := &Message{
		Topic:     *km.TopicPartition.Topic,
		Partition: km.TopicPartition.Partition,
		Offset:    int64(km.TopicPartition.Offset),
		Key:       km.Key,
		Value:     km.Value,
		Headers:   headers,
		Timestamp: km.Timestamp,
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
	if _, err := c.consumer.CommitMessage(km); err != nil {
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
		return c.consumer.Close()
	case <-ctx.Done():
		c.consumer.Close()
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

	// Check if we have an active subscription
	assignment, err := c.consumer.Assignment()
	if err != nil {
		return false
	}

	// Consumer is healthy if it has partition assignments
	return len(assignment) > 0
}
