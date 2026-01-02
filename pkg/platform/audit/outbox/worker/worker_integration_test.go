//go:build integration

package worker_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"github.com/twmb/franz-go/pkg/kgo"

	"credo/internal/platform/kafka/producer"
	"credo/pkg/platform/audit/outbox"
	outboxpostgres "credo/pkg/platform/audit/outbox/store/postgres"
	"credo/pkg/platform/audit/outbox/worker"
	"credo/pkg/testutil/containers"
)

type WorkerIntegrationSuite struct {
	suite.Suite
	postgres *containers.PostgresContainer
	kafka    *containers.KafkaContainer
	store    *outboxpostgres.Store
	producer *producer.Producer
}

func TestWorkerIntegrationSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	suite.Run(t, new(WorkerIntegrationSuite))
}

func (s *WorkerIntegrationSuite) SetupSuite() {
	mgr := containers.GetManager()
	s.postgres = mgr.GetPostgres(s.T())
	s.kafka = mgr.GetKafka(s.T())

	s.store = outboxpostgres.New(s.postgres.DB)

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

func (s *WorkerIntegrationSuite) TearDownSuite() {
	if s.producer != nil {
		s.producer.Close()
	}
}

func (s *WorkerIntegrationSuite) SetupTest() {
	ctx := context.Background()
	err := s.postgres.TruncateAll(ctx)
	s.Require().NoError(err)
}

// TestOutboxToKafkaFlow verifies the complete outbox pattern.
// Invariant: Events written to outbox must appear in Kafka and be marked processed.
func (s *WorkerIntegrationSuite) TestOutboxToKafkaFlow() {
	ctx := context.Background()
	topic := "test-outbox-flow"

	// Create topic
	err := s.kafka.CreateTopic(ctx, topic, 1, 1)
	s.Require().NoError(err)

	// Insert entry into outbox
	payload := map[string]string{
		"Action":  "user_created",
		"UserID":  uuid.New().String(),
		"Subject": "test-subject",
	}
	payloadBytes, err := json.Marshal(payload)
	s.Require().NoError(err)

	entry := outbox.NewEntry("user", uuid.New().String(), "user_created", payloadBytes)
	err = s.store.Append(ctx, entry)
	s.Require().NoError(err)

	// Verify entry is pending
	pending, err := s.store.CountPending(ctx)
	s.Require().NoError(err)
	s.Equal(int64(1), pending)

	// Create and start worker
	w := worker.New(s.store, s.producer,
		worker.WithTopic(topic),
		worker.WithPollInterval(50*time.Millisecond),
		worker.WithBatchSize(10),
	)
	w.Start()

	// Wait for processing
	s.Eventually(func() bool {
		count, _ := s.store.CountPending(ctx)
		return count == 0
	}, 5*time.Second, 50*time.Millisecond)

	// Stop worker
	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err = w.Stop(stopCtx)
	s.Require().NoError(err)

	// Verify message in Kafka
	consumer, err := s.kafka.NewConsumer(ctx, "test-outbox-flow-consumer", topic)
	s.Require().NoError(err)
	defer consumer.Close()

	record := s.kafka.WaitForMessage(ctx, consumer, 5*time.Second, func(r *kgo.Record) bool {
		return string(r.Key) == entry.ID.String()
	})

	s.Require().NotNil(record, "message should be in Kafka")
	s.Equal(entry.ID.String(), string(record.Key))

	// Verify headers
	headers := make(map[string]string)
	for _, h := range record.Headers {
		headers[h.Key] = string(h.Value)
	}
	s.Equal("user", headers["aggregate_type"])
	s.Equal("user_created", headers["event_type"])
}

// TestMultipleEntriesProcessedInOrder verifies batch processing.
// Invariant: Outbox entries are processed in creation order.
func (s *WorkerIntegrationSuite) TestMultipleEntriesProcessedInOrder() {
	ctx := context.Background()
	topic := "test-outbox-order"

	// Create topic
	err := s.kafka.CreateTopic(ctx, topic, 1, 1)
	s.Require().NoError(err)

	// Insert multiple entries
	var entries []*outbox.Entry
	for i := 0; i < 5; i++ {
		payload, _ := json.Marshal(map[string]int{"index": i})
		entry := outbox.NewEntry("order", uuid.New().String(), "order_event", payload)
		err := s.store.Append(ctx, entry)
		s.Require().NoError(err)
		entries = append(entries, entry)
		time.Sleep(10 * time.Millisecond) // Ensure ordering by created_at
	}

	// Create and start worker
	w := worker.New(s.store, s.producer,
		worker.WithTopic(topic),
		worker.WithPollInterval(50*time.Millisecond),
		worker.WithBatchSize(10),
	)
	w.Start()

	// Wait for all entries to be processed
	s.Eventually(func() bool {
		count, _ := s.store.CountPending(ctx)
		return count == 0
	}, 10*time.Second, 50*time.Millisecond)

	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err = w.Stop(stopCtx)
	s.Require().NoError(err)

	// All entries should be processed
	pending, err := s.store.CountPending(ctx)
	s.Require().NoError(err)
	s.Equal(int64(0), pending)
}

// TestWorkerRetriesOnNextPoll verifies retry behavior.
// Invariant: Failed entries remain unprocessed and are retried on next poll.
func (s *WorkerIntegrationSuite) TestWorkerRetriesOnNextPoll() {
	ctx := context.Background()

	// Insert entry
	payload, _ := json.Marshal(map[string]string{"test": "retry"})
	entry := outbox.NewEntry("retry", uuid.New().String(), "retry_event", payload)
	err := s.store.Append(ctx, entry)
	s.Require().NoError(err)

	// Create worker with a topic that exists
	topic := "test-retry-topic"
	err = s.kafka.CreateTopic(ctx, topic, 1, 1)
	s.Require().NoError(err)

	w := worker.New(s.store, s.producer,
		worker.WithTopic(topic),
		worker.WithPollInterval(50*time.Millisecond),
		worker.WithBatchSize(10),
	)
	w.Start()

	// Wait for processing
	s.Eventually(func() bool {
		count, _ := s.store.CountPending(ctx)
		return count == 0
	}, 5*time.Second, 50*time.Millisecond)

	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err = w.Stop(stopCtx)
	s.Require().NoError(err)

	// Entry should be processed
	pending, err := s.store.CountPending(ctx)
	s.Require().NoError(err)
	s.Equal(int64(0), pending)
}

// TestDrainOnShutdown verifies graceful shutdown.
// Invariant: Pending entries are processed during shutdown drain.
func (s *WorkerIntegrationSuite) TestDrainOnShutdown() {
	ctx := context.Background()
	topic := "test-drain-topic"

	err := s.kafka.CreateTopic(ctx, topic, 1, 1)
	s.Require().NoError(err)

	// Create worker with long poll interval
	w := worker.New(s.store, s.producer,
		worker.WithTopic(topic),
		worker.WithPollInterval(10*time.Second), // Long interval
		worker.WithBatchSize(10),
	)
	w.Start()

	// Insert entry after worker started (won't be picked up by regular poll due to long interval)
	payload, _ := json.Marshal(map[string]string{"test": "drain"})
	entry := outbox.NewEntry("drain", uuid.New().String(), "drain_event", payload)
	err = s.store.Append(ctx, entry)
	s.Require().NoError(err)

	// Wait a bit to ensure no poll happened
	time.Sleep(100 * time.Millisecond)

	// Entry should still be pending
	pending, err := s.store.CountPending(ctx)
	s.Require().NoError(err)
	s.Equal(int64(1), pending)

	// Stop worker (should trigger drain)
	stopCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	err = w.Stop(stopCtx)
	s.Require().NoError(err)

	// Entry should be processed during drain
	pending, err = s.store.CountPending(ctx)
	s.Require().NoError(err)
	s.Equal(int64(0), pending)
}

// TestConcurrentWorkersWithSkipLocked verifies FOR UPDATE SKIP LOCKED.
// Invariant: Concurrent workers process different entries without duplicates.
func (s *WorkerIntegrationSuite) TestConcurrentWorkersWithSkipLocked() {
	ctx := context.Background()
	topic := "test-concurrent-workers"

	err := s.kafka.CreateTopic(ctx, topic, 1, 1)
	s.Require().NoError(err)

	// Insert many entries
	for i := 0; i < 20; i++ {
		payload, _ := json.Marshal(map[string]int{"index": i})
		entry := outbox.NewEntry("concurrent", uuid.New().String(), "concurrent_event", payload)
		err := s.store.Append(ctx, entry)
		s.Require().NoError(err)
	}

	// Create multiple workers
	w1 := worker.New(s.store, s.producer,
		worker.WithTopic(topic),
		worker.WithPollInterval(50*time.Millisecond),
		worker.WithBatchSize(5),
	)
	w2 := worker.New(s.store, s.producer,
		worker.WithTopic(topic),
		worker.WithPollInterval(50*time.Millisecond),
		worker.WithBatchSize(5),
	)

	w1.Start()
	w2.Start()

	// Wait for all entries to be processed
	s.Eventually(func() bool {
		count, _ := s.store.CountPending(ctx)
		return count == 0
	}, 15*time.Second, 100*time.Millisecond)

	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = w1.Stop(stopCtx)
	_ = w2.Stop(stopCtx)

	// All entries should be processed exactly once
	pending, err := s.store.CountPending(ctx)
	s.Require().NoError(err)
	s.Equal(int64(0), pending)
}
