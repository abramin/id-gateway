//go:build integration

package consumer_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/twmb/franz-go/pkg/kgo"

	"credo/internal/platform/kafka/consumer"
	"credo/internal/platform/kafka/producer"
	"credo/pkg/testutil/containers"
)

type ConsumerIntegrationSuite struct {
	suite.Suite
	kafka    *containers.KafkaContainer
	producer *producer.Producer
}

func TestConsumerIntegrationSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	suite.Run(t, new(ConsumerIntegrationSuite))
}

func (s *ConsumerIntegrationSuite) SetupSuite() {
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

func (s *ConsumerIntegrationSuite) TearDownSuite() {
	if s.producer != nil {
		s.producer.Close()
	}
}

// testHandler is a simple handler for testing.
type testHandler struct {
	mu       sync.Mutex
	messages []*consumer.Message
	errFunc  func(*consumer.Message) error
}

func newTestHandler() *testHandler {
	return &testHandler{}
}

func (h *testHandler) Handle(ctx context.Context, msg *consumer.Message) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.errFunc != nil {
		if err := h.errFunc(msg); err != nil {
			return err
		}
	}

	h.messages = append(h.messages, msg)
	return nil
}

func (h *testHandler) Messages() []*consumer.Message {
	h.mu.Lock()
	defer h.mu.Unlock()
	result := make([]*consumer.Message, len(h.messages))
	copy(result, h.messages)
	return result
}

// TestConsumerReceivesMessages verifies basic message delivery.
// Invariant: Messages produced to a topic are delivered to subscribed consumers.
func (s *ConsumerIntegrationSuite) TestConsumerReceivesMessages() {
	ctx := context.Background()
	topic := "test-consumer-receives"

	// Create topic
	err := s.kafka.CreateTopic(ctx, topic, 1, 1)
	s.Require().NoError(err)

	// Produce messages
	for i := 0; i < 3; i++ {
		msg := &producer.Message{
			Topic: topic,
			Key:   []byte("key"),
			Value: []byte("value"),
		}
		err = s.producer.Produce(ctx, msg)
		s.Require().NoError(err)
	}

	// Create and start consumer
	handler := newTestHandler()
	cfg := consumer.Config{
		Brokers:         s.kafka.Brokers,
		GroupID:         "test-consumer-receives-group",
		AutoOffsetReset: "earliest",
	}
	cons, err := consumer.New(cfg, handler, nil)
	s.Require().NoError(err)

	err = cons.Subscribe([]string{topic})
	s.Require().NoError(err)

	cons.Start()

	// Wait for messages
	s.Eventually(func() bool {
		return len(handler.Messages()) >= 3
	}, 10*time.Second, 100*time.Millisecond)

	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err = cons.Stop(stopCtx)
	s.Require().NoError(err)

	s.GreaterOrEqual(len(handler.Messages()), 3)
}

// TestConsumerPreservesHeaders verifies header delivery.
// Invariant: Message headers are preserved through the consumer pipeline.
func (s *ConsumerIntegrationSuite) TestConsumerPreservesHeaders() {
	ctx := context.Background()
	topic := "test-consumer-headers"

	// Create topic
	err := s.kafka.CreateTopic(ctx, topic, 1, 1)
	s.Require().NoError(err)

	// Produce message with headers
	msg := &producer.Message{
		Topic: topic,
		Key:   []byte("header-key"),
		Value: []byte("header-value"),
		Headers: map[string]string{
			"trace-id":   "abc123",
			"event_type": "test_event",
		},
	}
	err = s.producer.Produce(ctx, msg)
	s.Require().NoError(err)

	// Create and start consumer
	handler := newTestHandler()
	cfg := consumer.Config{
		Brokers:         s.kafka.Brokers,
		GroupID:         "test-consumer-headers-group",
		AutoOffsetReset: "earliest",
	}
	cons, err := consumer.New(cfg, handler, nil)
	s.Require().NoError(err)

	err = cons.Subscribe([]string{topic})
	s.Require().NoError(err)

	cons.Start()

	// Wait for message
	s.Eventually(func() bool {
		return len(handler.Messages()) >= 1
	}, 10*time.Second, 100*time.Millisecond)

	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err = cons.Stop(stopCtx)
	s.Require().NoError(err)

	s.Require().GreaterOrEqual(len(handler.Messages()), 1)
	received := handler.Messages()[0]
	s.Equal("abc123", received.Headers["trace-id"])
	s.Equal("test_event", received.Headers["event_type"])
}

// TestManualCommitOnSuccessOnly verifies at-least-once delivery.
// Invariant: Offset commits only after handler returns nil.
func (s *ConsumerIntegrationSuite) TestManualCommitOnSuccessOnly() {
	ctx := context.Background()
	topic := "test-manual-commit"

	// Create topic
	err := s.kafka.CreateTopic(ctx, topic, 1, 1)
	s.Require().NoError(err)

	// Produce message
	msg := &producer.Message{
		Topic: topic,
		Key:   []byte("commit-test-key"),
		Value: []byte("commit-test-value"),
	}
	err = s.producer.Produce(ctx, msg)
	s.Require().NoError(err)

	groupID := "test-manual-commit-group-" + time.Now().Format("20060102150405")

	// First consumer: fail on first message
	var failCount atomic.Int32
	failingHandler := newTestHandler()
	failingHandler.errFunc = func(m *consumer.Message) error {
		if failCount.Add(1) == 1 {
			return context.DeadlineExceeded // Simulate failure
		}
		return nil
	}

	cfg1 := consumer.Config{
		Brokers:         s.kafka.Brokers,
		GroupID:         groupID,
		AutoOffsetReset: "earliest",
	}
	cons1, err := consumer.New(cfg1, failingHandler, nil)
	s.Require().NoError(err)

	err = cons1.Subscribe([]string{topic})
	s.Require().NoError(err)

	cons1.Start()

	// Wait for at least one failure attempt
	s.Eventually(func() bool {
		return failCount.Load() >= 1
	}, 10*time.Second, 100*time.Millisecond)

	// Stop first consumer (offset should NOT be committed because handler failed)
	stopCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	_ = cons1.Stop(stopCtx)
	cancel()

	// Second consumer: same group, should receive the message again
	successHandler := newTestHandler()
	cfg2 := consumer.Config{
		Brokers:         s.kafka.Brokers,
		GroupID:         groupID,
		AutoOffsetReset: "earliest",
	}
	cons2, err := consumer.New(cfg2, successHandler, nil)
	s.Require().NoError(err)

	err = cons2.Subscribe([]string{topic})
	s.Require().NoError(err)

	cons2.Start()

	// Wait for message redelivery
	s.Eventually(func() bool {
		return len(successHandler.Messages()) >= 1
	}, 10*time.Second, 100*time.Millisecond)

	stopCtx2, cancel2 := context.WithTimeout(ctx, 5*time.Second)
	defer cancel2()
	err = cons2.Stop(stopCtx2)
	s.Require().NoError(err)

	// Message should have been redelivered
	s.GreaterOrEqual(len(successHandler.Messages()), 1)
}

// TestConsumerHealthy verifies health check works.
// Invariant: Healthy() returns true when broker is reachable.
func (s *ConsumerIntegrationSuite) TestConsumerHealthy() {
	ctx := context.Background()

	handler := newTestHandler()
	cfg := consumer.Config{
		Brokers:         s.kafka.Brokers,
		GroupID:         "test-healthy-group",
		AutoOffsetReset: "earliest",
	}
	cons, err := consumer.New(cfg, handler, nil)
	s.Require().NoError(err)

	s.True(cons.Healthy(ctx))

	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = cons.Stop(stopCtx)
}

// rawProduceMessage produces a message directly via franz-go for test setup.
func (s *ConsumerIntegrationSuite) rawProduceMessage(ctx context.Context, topic string, key, value []byte, headers map[string]string) error {
	client, err := kgo.NewClient(kgo.SeedBrokers(s.kafka.Brokers))
	if err != nil {
		return err
	}
	defer client.Close()

	var kgoHeaders []kgo.RecordHeader
	for k, v := range headers {
		kgoHeaders = append(kgoHeaders, kgo.RecordHeader{Key: k, Value: []byte(v)})
	}

	record := &kgo.Record{
		Topic:   topic,
		Key:     key,
		Value:   value,
		Headers: kgoHeaders,
	}

	results := client.ProduceSync(ctx, record)
	return results.FirstErr()
}
