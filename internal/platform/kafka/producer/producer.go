package producer

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

// Message represents a message to be published to Kafka.
type Message struct {
	Topic   string
	Key     []byte
	Value   []byte
	Headers map[string]string
}

// Producer wraps the franz-go client with a simpler interface.
type Producer struct {
	client *kgo.Client
	logger *slog.Logger
	mu     sync.RWMutex
	closed bool
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

	brokers := strings.Split(cfg.Brokers, ",")

	// Map acks setting
	var acks kgo.Acks
	switch cfg.Acks {
	case "0":
		acks = kgo.NoAck()
	case "1":
		acks = kgo.LeaderAck()
	default:
		acks = kgo.AllISRAcks()
	}

	opts := []kgo.Opt{
		kgo.SeedBrokers(brokers...),
		kgo.RequiredAcks(acks),
		kgo.RecordRetries(cfg.Retries),
		kgo.ProducerBatchMaxBytes(16384),
		kgo.ProducerLinger(5 * time.Millisecond),
		kgo.AllowAutoTopicCreation(),
	}

	if cfg.DeliveryTimeout > 0 {
		opts = append(opts, kgo.RecordDeliveryTimeout(cfg.DeliveryTimeout))
	}

	client, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("create kafka producer: %w", err)
	}

	return &Producer{
		client: client,
		logger: logger,
	}, nil
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

	// Convert headers
	var headers []kgo.RecordHeader
	for k, v := range msg.Headers {
		headers = append(headers, kgo.RecordHeader{Key: k, Value: []byte(v)})
	}

	record := &kgo.Record{
		Topic:   msg.Topic,
		Key:     msg.Key,
		Value:   msg.Value,
		Headers: headers,
	}

	// ProduceSync waits for the record to be acknowledged
	results := p.client.ProduceSync(ctx, record)
	if err := results.FirstErr(); err != nil {
		return fmt.Errorf("produce message: %w", err)
	}

	return nil
}

// ProduceAsync sends a message to Kafka asynchronously.
// The message is buffered and will be delivered in the background.
func (p *Producer) ProduceAsync(msg *Message) error {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return fmt.Errorf("producer is closed")
	}
	p.mu.RUnlock()

	// Convert headers
	var headers []kgo.RecordHeader
	for k, v := range msg.Headers {
		headers = append(headers, kgo.RecordHeader{Key: k, Value: []byte(v)})
	}

	record := &kgo.Record{
		Topic:   msg.Topic,
		Key:     msg.Key,
		Value:   msg.Value,
		Headers: headers,
	}

	p.client.Produce(context.Background(), record, func(r *kgo.Record, err error) {
		if err != nil && p.logger != nil {
			p.logger.Error("kafka delivery failed",
				"topic", r.Topic,
				"partition", r.Partition,
				"error", err,
			)
		}
	})

	return nil
}

// Flush waits for all buffered messages to be delivered.
func (p *Producer) Flush(timeout time.Duration) int {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := p.client.Flush(ctx); err != nil {
		// Return 1 to indicate unflushed messages on error
		return 1
	}
	return 0
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

	// Flush remaining messages with 30 second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := p.client.Flush(ctx); err != nil {
		if p.logger != nil {
			p.logger.Warn("kafka producer closed with unflushed messages",
				"error", err,
			)
		}
	}

	p.client.Close()
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

	// Ping the brokers to check connectivity
	if err := p.client.Ping(ctx); err != nil {
		return false
	}
	return true
}

// Len returns the number of messages in the producer buffer.
func (p *Producer) Len() int {
	return int(p.client.BufferedProduceRecords())
}

// NewNoopProducer creates a producer that discards all messages.
// Useful for testing or when Kafka is disabled.
func NewNoopProducer(logger *slog.Logger) *NoopProducer {
	return &NoopProducer{logger: logger}
}

// NoopProducer is a producer that discards all messages.
type NoopProducer struct {
	logger *slog.Logger
}

// Produce discards the message.
func (p *NoopProducer) Produce(ctx context.Context, msg *Message) error {
	return nil
}

// ProduceAsync discards the message.
func (p *NoopProducer) ProduceAsync(msg *Message) error {
	return nil
}

// Flush is a no-op.
func (p *NoopProducer) Flush(timeout time.Duration) int {
	return 0
}

// Close is a no-op.
func (p *NoopProducer) Close() error {
	return nil
}

// Healthy always returns true.
func (p *NoopProducer) Healthy(ctx context.Context) bool {
	return true
}

// Len always returns 0.
func (p *NoopProducer) Len() int {
	return 0
}

// Dialer returns a custom dialer for the Kafka client.
// This can be used to customize connection behavior.
func Dialer(timeout time.Duration) func(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{
		Timeout: timeout,
	}).DialContext
}
