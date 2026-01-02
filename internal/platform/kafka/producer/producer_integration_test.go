//go:build integration

package producer_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/twmb/franz-go/pkg/kgo"

	"credo/internal/platform/kafka/producer"
	"credo/pkg/testutil/containers"
)

type ProducerIntegrationSuite struct {
	suite.Suite
	kafka    *containers.KafkaContainer
	producer *producer.Producer
}

func TestProducerIntegrationSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	suite.Run(t, new(ProducerIntegrationSuite))
}

func (s *ProducerIntegrationSuite) SetupSuite() {
	mgr := containers.GetManager()
	s.kafka = mgr.GetKafka(s.T())

	cfg := producer.Config{
		Brokers:         s.kafka.Brokers,
		Acks:            "all",
		Retries:         3,
		DeliveryTimeout: 10 * time.Second,
	}
	prod, err := producer.New(cfg, nil)
	s.Require().NoError(err)
	s.producer = prod
}

func (s *ProducerIntegrationSuite) TearDownSuite() {
	if s.producer != nil {
		s.producer.Close()
	}
}

// TestProduceSyncDeliversMessage verifies synchronous produce actually delivers.
// Invariant: ProduceSync only returns success after broker acknowledgment.
func (s *ProducerIntegrationSuite) TestProduceSyncDeliversMessage() {
	ctx := context.Background()
	topic := "test-produce-sync"

	// Create topic
	err := s.kafka.CreateTopic(ctx, topic, 1, 1)
	s.Require().NoError(err)

	// Produce message
	msg := &producer.Message{
		Topic: topic,
		Key:   []byte("test-key"),
		Value: []byte("test-value"),
	}

	err = s.producer.Produce(ctx, msg)
	s.Require().NoError(err)

	// Create consumer to verify
	consumer, err := s.kafka.NewConsumer(ctx, "test-consumer-group", topic)
	s.Require().NoError(err)
	defer consumer.Close()

	// Wait for message
	record := s.kafka.WaitForMessage(ctx, consumer, 5*time.Second, func(r *kgo.Record) bool {
		return string(r.Key) == "test-key"
	})

	s.Require().NotNil(record, "message should be consumable")
	s.Equal("test-value", string(record.Value))
}

// TestProducePreservesHeaders verifies header propagation.
// Invariant: All headers set on message must be retrievable by consumer.
func (s *ProducerIntegrationSuite) TestProducePreservesHeaders() {
	ctx := context.Background()
	topic := "test-produce-headers"

	// Create topic
	err := s.kafka.CreateTopic(ctx, topic, 1, 1)
	s.Require().NoError(err)

	// Produce message with headers
	msg := &producer.Message{
		Topic: topic,
		Key:   []byte("header-test-key"),
		Value: []byte("header-test-value"),
		Headers: map[string]string{
			"trace-id":       "12345",
			"aggregate_type": "user",
			"event_type":     "user_created",
		},
	}

	err = s.producer.Produce(ctx, msg)
	s.Require().NoError(err)

	// Create consumer to verify
	consumer, err := s.kafka.NewConsumer(ctx, "test-headers-consumer-group", topic)
	s.Require().NoError(err)
	defer consumer.Close()

	// Wait for message
	record := s.kafka.WaitForMessage(ctx, consumer, 5*time.Second, func(r *kgo.Record) bool {
		return string(r.Key) == "header-test-key"
	})

	s.Require().NotNil(record, "message should be consumable")

	// Verify headers
	headers := make(map[string]string)
	for _, h := range record.Headers {
		headers[h.Key] = string(h.Value)
	}

	s.Equal("12345", headers["trace-id"])
	s.Equal("user", headers["aggregate_type"])
	s.Equal("user_created", headers["event_type"])
}

// TestProduceToNonExistentTopicAutoCreates verifies auto-topic creation.
// Invariant: Redpanda auto-creates topics on first produce.
func (s *ProducerIntegrationSuite) TestProduceToNonExistentTopicAutoCreates() {
	ctx := context.Background()
	topic := "test-auto-create-" + time.Now().Format("20060102150405")

	msg := &producer.Message{
		Topic: topic,
		Key:   []byte("auto-create-key"),
		Value: []byte("auto-create-value"),
	}

	err := s.producer.Produce(ctx, msg)
	s.Require().NoError(err)

	// Verify message is consumable
	consumer, err := s.kafka.NewConsumer(ctx, "test-auto-create-consumer", topic)
	s.Require().NoError(err)
	defer consumer.Close()

	record := s.kafka.WaitForMessage(ctx, consumer, 5*time.Second, func(r *kgo.Record) bool {
		return string(r.Key) == "auto-create-key"
	})

	s.Require().NotNil(record, "message should be consumable from auto-created topic")
}

// TestProducerHealthy verifies health check works with running broker.
// Invariant: Healthy() returns true when broker is reachable.
func (s *ProducerIntegrationSuite) TestProducerHealthy() {
	ctx := context.Background()
	s.True(s.producer.Healthy(ctx))
}
