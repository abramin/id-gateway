package producer

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
)

// Message represents a message to be published to Kafka.
type Message struct {
	Topic   string
	Key     []byte
	Value   []byte
	Headers map[string]string
}

// Producer wraps the confluent-kafka-go producer with a simpler interface.
type Producer struct {
	producer *kafka.Producer
	logger   *slog.Logger
	mu       sync.RWMutex
	closed   bool
}

// Config holds producer configuration.
type Config struct {
	Brokers         string
	Acks            string
	Retries         int
	DeliveryTimeout time.Duration
}

// New creates a new Kafka producer.
func New(cfg Config, logger *slog.Logger) (*Producer, error) {
	if cfg.Brokers == "" {
		return nil, fmt.Errorf("kafka brokers not configured")
	}

	configMap := &kafka.ConfigMap{
		"bootstrap.servers":  cfg.Brokers,
		"acks":               cfg.Acks,
		"retries":            cfg.Retries,
		"delivery.timeout.ms": int(cfg.DeliveryTimeout.Milliseconds()),
		"linger.ms":          5,  // Small batching for low latency
		"batch.size":         16384,
	}

	producer, err := kafka.NewProducer(configMap)
	if err != nil {
		return nil, fmt.Errorf("create kafka producer: %w", err)
	}

	p := &Producer{
		producer: producer,
		logger:   logger,
	}

	// Start delivery report handler
	go p.handleDeliveryReports()

	return p, nil
}

// handleDeliveryReports processes delivery reports in the background.
func (p *Producer) handleDeliveryReports() {
	for e := range p.producer.Events() {
		switch ev := e.(type) {
		case *kafka.Message:
			if ev.TopicPartition.Error != nil {
				p.logger.Error("kafka delivery failed",
					"topic", *ev.TopicPartition.Topic,
					"partition", ev.TopicPartition.Partition,
					"error", ev.TopicPartition.Error,
				)
			}
		case kafka.Error:
			p.logger.Error("kafka producer error",
				"code", ev.Code(),
				"error", ev.Error(),
			)
		}
	}
}

// Produce sends a message to Kafka synchronously.
// It waits for the delivery report before returning.
func (p *Producer) Produce(ctx context.Context, msg *Message) error {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return fmt.Errorf("producer is closed")
	}
	p.mu.RUnlock()

	deliveryChan := make(chan kafka.Event, 1)

	// Convert headers
	var headers []kafka.Header
	for k, v := range msg.Headers {
		headers = append(headers, kafka.Header{Key: k, Value: []byte(v)})
	}

	kafkaMsg := &kafka.Message{
		TopicPartition: kafka.TopicPartition{
			Topic:     &msg.Topic,
			Partition: kafka.PartitionAny,
		},
		Key:     msg.Key,
		Value:   msg.Value,
		Headers: headers,
	}

	if err := p.producer.Produce(kafkaMsg, deliveryChan); err != nil {
		return fmt.Errorf("produce message: %w", err)
	}

	// Wait for delivery report or context cancellation
	select {
	case e := <-deliveryChan:
		m := e.(*kafka.Message)
		if m.TopicPartition.Error != nil {
			return fmt.Errorf("message delivery failed: %w", m.TopicPartition.Error)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ProduceAsync sends a message to Kafka asynchronously.
// The message is buffered and will be delivered by the background handler.
func (p *Producer) ProduceAsync(msg *Message) error {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return fmt.Errorf("producer is closed")
	}
	p.mu.RUnlock()

	// Convert headers
	var headers []kafka.Header
	for k, v := range msg.Headers {
		headers = append(headers, kafka.Header{Key: k, Value: []byte(v)})
	}

	kafkaMsg := &kafka.Message{
		TopicPartition: kafka.TopicPartition{
			Topic:     &msg.Topic,
			Partition: kafka.PartitionAny,
		},
		Key:     msg.Key,
		Value:   msg.Value,
		Headers: headers,
	}

	return p.producer.Produce(kafkaMsg, nil)
}

// Flush waits for all buffered messages to be delivered.
func (p *Producer) Flush(timeout time.Duration) int {
	return p.producer.Flush(int(timeout.Milliseconds()))
}

// Close gracefully shuts down the producer.
func (p *Producer) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()

	// Flush remaining messages
	remaining := p.producer.Flush(30000) // 30 second timeout
	if remaining > 0 {
		p.logger.Warn("kafka producer closed with unflushed messages",
			"remaining", remaining,
		)
	}

	p.producer.Close()
	return nil
}

// Healthy checks if the producer can communicate with brokers.
func (p *Producer) Healthy(ctx context.Context) bool {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return false
	}
	p.mu.RUnlock()

	// A successful flush with timeout 0 indicates the producer is healthy
	remaining := p.producer.Flush(0)
	return remaining == 0
}

// Len returns the number of messages in the producer queue.
func (p *Producer) Len() int {
	return p.producer.Len()
}
