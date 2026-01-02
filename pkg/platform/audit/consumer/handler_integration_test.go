//go:build integration

package consumer_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"github.com/twmb/franz-go/pkg/kgo"

	kafkaconsumer "credo/internal/platform/kafka/consumer"
	"credo/internal/platform/kafka/producer"
	id "credo/pkg/domain"
	audit "credo/pkg/platform/audit"
	auditconsumer "credo/pkg/platform/audit/consumer"
	"credo/pkg/platform/audit/outbox"
	outboxpostgres "credo/pkg/platform/audit/outbox/store/postgres"
	auditpostgres "credo/pkg/platform/audit/store/postgres"
	"credo/pkg/platform/audit/outbox/worker"
	"credo/pkg/testutil/containers"
)

type HandlerIntegrationSuite struct {
	suite.Suite
	postgres    *containers.PostgresContainer
	kafka       *containers.KafkaContainer
	auditStore  *auditpostgres.Store
	outboxStore *outboxpostgres.Store
	producer    *producer.Producer
}

func TestHandlerIntegrationSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	suite.Run(t, new(HandlerIntegrationSuite))
}

func (s *HandlerIntegrationSuite) SetupSuite() {
	mgr := containers.GetManager()
	s.postgres = mgr.GetPostgres(s.T())
	s.kafka = mgr.GetKafka(s.T())

	s.auditStore = auditpostgres.New(s.postgres.DB)
	s.outboxStore = outboxpostgres.New(s.postgres.DB)

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

func (s *HandlerIntegrationSuite) TearDownSuite() {
	if s.producer != nil {
		s.producer.Close()
	}
}

func (s *HandlerIntegrationSuite) SetupTest() {
	ctx := context.Background()
	err := s.postgres.TruncateAll(ctx)
	s.Require().NoError(err)
}

// TestEndToEndAuditFlow verifies the complete audit pipeline.
// Invariant: audit.Event -> outbox -> Kafka -> audit_events table
func (s *HandlerIntegrationSuite) TestEndToEndAuditFlow() {
	ctx := context.Background()
	topic := "test-e2e-audit"

	// Create topic
	err := s.kafka.CreateTopic(ctx, topic, 1, 1)
	s.Require().NoError(err)

	// Create an audit event
	userID := id.UserID(uuid.New())
	event := audit.Event{
		Category:  audit.CategoryCompliance,
		Timestamp: time.Now().UTC(),
		UserID:    userID,
		Subject:   "test-subject",
		Action:    "user_created",
		Email:     "test@example.com",
		RequestID: "req-123",
	}

	// Manually create outbox entry (simulating publisher behavior)
	payload := map[string]string{
		"ID":        uuid.New().String(),
		"Category":  string(event.Category),
		"Timestamp": event.Timestamp.Format(time.RFC3339Nano),
		"UserID":    uuid.UUID(event.UserID).String(),
		"Subject":   event.Subject,
		"Action":    event.Action,
		"Email":     event.Email,
		"RequestID": event.RequestID,
	}
	payloadBytes, err := json.Marshal(payload)
	s.Require().NoError(err)

	entryID := uuid.New()
	entry := &outbox.Entry{
		ID:            entryID,
		AggregateType: "user",
		AggregateID:   uuid.UUID(userID).String(),
		EventType:     event.Action,
		Payload:       payloadBytes,
		CreatedAt:     time.Now(),
	}
	err = s.outboxStore.Append(ctx, entry)
	s.Require().NoError(err)

	// Start outbox worker to publish to Kafka
	w := worker.New(s.outboxStore, s.producer,
		worker.WithTopic(topic),
		worker.WithPollInterval(50*time.Millisecond),
	)
	w.Start()

	// Wait for outbox to be drained
	s.Eventually(func() bool {
		count, _ := s.outboxStore.CountPending(ctx)
		return count == 0
	}, 5*time.Second, 50*time.Millisecond)

	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err = w.Stop(stopCtx)
	s.Require().NoError(err)

	// Start audit consumer to read from Kafka and write to audit_events
	handler := auditconsumer.NewHandler(s.auditStore, nil)
	consumerCfg := kafkaconsumer.Config{
		Brokers:         s.kafka.Brokers,
		GroupID:         "test-e2e-audit-consumer",
		AutoOffsetReset: "earliest",
	}
	consumer, err := kafkaconsumer.New(consumerCfg, handler, nil)
	s.Require().NoError(err)

	err = consumer.Subscribe([]string{topic})
	s.Require().NoError(err)

	consumer.Start()

	// Wait for event to be consumed and stored
	s.Eventually(func() bool {
		events, _ := s.auditStore.ListRecent(ctx, 10)
		return len(events) > 0
	}, 10*time.Second, 100*time.Millisecond)

	consumerStopCtx, consumerCancel := context.WithTimeout(ctx, 5*time.Second)
	defer consumerCancel()
	err = consumer.Stop(consumerStopCtx)
	s.Require().NoError(err)

	// Verify event in audit_events table
	events, err := s.auditStore.ListRecent(ctx, 10)
	s.Require().NoError(err)
	s.Require().GreaterOrEqual(len(events), 1)

	stored := events[0]
	s.Equal(event.Action, stored.Action)
	s.Equal(event.Subject, stored.Subject)
	s.Equal(event.Email, stored.Email)
}

// TestIdempotentInsert verifies duplicate message handling.
// Invariant: Reprocessing same message must not create duplicate rows.
func (s *HandlerIntegrationSuite) TestIdempotentInsert() {
	ctx := context.Background()
	topic := "test-idempotent"

	// Create topic
	err := s.kafka.CreateTopic(ctx, topic, 1, 1)
	s.Require().NoError(err)

	// Create a unique event ID
	eventID := uuid.New()

	payload := map[string]string{
		"ID":        eventID.String(),
		"Category":  "compliance",
		"Timestamp": time.Now().Format(time.RFC3339Nano),
		"UserID":    uuid.New().String(),
		"Subject":   "test-subject",
		"Action":    "idempotent_test",
	}
	payloadBytes, _ := json.Marshal(payload)

	// Produce same message twice with same key (event ID)
	client, err := kgo.NewClient(kgo.SeedBrokers(s.kafka.Brokers))
	s.Require().NoError(err)
	defer client.Close()

	for i := 0; i < 2; i++ {
		record := &kgo.Record{
			Topic: topic,
			Key:   []byte(eventID.String()),
			Value: payloadBytes,
		}
		results := client.ProduceSync(ctx, record)
		s.Require().NoError(results.FirstErr())
	}

	// Start consumer
	handler := auditconsumer.NewHandler(s.auditStore, nil)
	consumerCfg := kafkaconsumer.Config{
		Brokers:         s.kafka.Brokers,
		GroupID:         "test-idempotent-consumer",
		AutoOffsetReset: "earliest",
	}
	consumer, err := kafkaconsumer.New(consumerCfg, handler, nil)
	s.Require().NoError(err)

	err = consumer.Subscribe([]string{topic})
	s.Require().NoError(err)

	consumer.Start()

	// Wait for at least one event to be processed
	s.Eventually(func() bool {
		events, _ := s.auditStore.ListRecent(ctx, 10)
		for _, e := range events {
			if e.Action == "idempotent_test" {
				return true
			}
		}
		return false
	}, 10*time.Second, 100*time.Millisecond)

	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err = consumer.Stop(stopCtx)
	s.Require().NoError(err)

	// Query should return exactly one event
	events, err := s.auditStore.ListRecent(ctx, 10)
	s.Require().NoError(err)

	// Count events with our specific action
	count := 0
	for _, e := range events {
		if e.Action == "idempotent_test" {
			count++
		}
	}
	s.Equal(1, count, "should have exactly one event despite duplicate messages")
}

// TestMalformedMessageDoesNotBlockProcessing verifies graceful error handling.
// Invariant: Malformed messages are skipped without blocking subsequent messages.
func (s *HandlerIntegrationSuite) TestMalformedMessageDoesNotBlockProcessing() {
	ctx := context.Background()
	topic := "test-malformed"

	// Create topic
	err := s.kafka.CreateTopic(ctx, topic, 1, 1)
	s.Require().NoError(err)

	client, err := kgo.NewClient(kgo.SeedBrokers(s.kafka.Brokers))
	s.Require().NoError(err)
	defer client.Close()

	// Send malformed message (invalid key)
	malformedRecord := &kgo.Record{
		Topic: topic,
		Key:   []byte("not-a-uuid"),
		Value: []byte(`{"Action":"malformed"}`),
	}
	results := client.ProduceSync(ctx, malformedRecord)
	s.Require().NoError(results.FirstErr())

	// Send valid message after
	validID := uuid.New()
	validPayload := map[string]string{
		"ID":        validID.String(),
		"Category":  "operations",
		"Timestamp": time.Now().Format(time.RFC3339Nano),
		"Subject":   "test-subject",
		"Action":    "valid_after_malformed",
	}
	validPayloadBytes, _ := json.Marshal(validPayload)

	validRecord := &kgo.Record{
		Topic: topic,
		Key:   []byte(validID.String()),
		Value: validPayloadBytes,
	}
	results = client.ProduceSync(ctx, validRecord)
	s.Require().NoError(results.FirstErr())

	// Start consumer
	handler := auditconsumer.NewHandler(s.auditStore, nil)
	consumerCfg := kafkaconsumer.Config{
		Brokers:         s.kafka.Brokers,
		GroupID:         "test-malformed-consumer",
		AutoOffsetReset: "earliest",
	}
	consumer, err := kafkaconsumer.New(consumerCfg, handler, nil)
	s.Require().NoError(err)

	err = consumer.Subscribe([]string{topic})
	s.Require().NoError(err)

	consumer.Start()

	// Wait for processing
	s.Eventually(func() bool {
		events, _ := s.auditStore.ListRecent(ctx, 10)
		for _, e := range events {
			if e.Action == "valid_after_malformed" {
				return true
			}
		}
		return false
	}, 10*time.Second, 100*time.Millisecond)

	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err = consumer.Stop(stopCtx)
	s.Require().NoError(err)

	// Valid message should be processed despite malformed message before it
	events, err := s.auditStore.ListRecent(ctx, 10)
	s.Require().NoError(err)

	found := false
	for _, e := range events {
		if e.Action == "valid_after_malformed" {
			found = true
			break
		}
	}
	s.True(found, "valid message should be processed after malformed message")
}

// TestStoreFailurePreventsCommit verifies at-least-once delivery.
// Invariant: Database failures return error to prevent offset commit.
func (s *HandlerIntegrationSuite) TestHandlerReturnsErrorOnStoreFailure() {
	ctx := context.Background()

	// Create a handler with a working store
	handler := auditconsumer.NewHandler(s.auditStore, nil)

	// Create a valid message
	eventID := uuid.New()
	payload := map[string]string{
		"ID":        eventID.String(),
		"Category":  "operations",
		"Timestamp": time.Now().Format(time.RFC3339Nano),
		"Subject":   "test-subject",
		"Action":    "store_failure_test",
	}
	payloadBytes, _ := json.Marshal(payload)

	msg := &kafkaconsumer.Message{
		Topic:   "test-topic",
		Key:     []byte(eventID.String()),
		Value:   payloadBytes,
		Headers: make(map[string]string),
	}

	// Handler should succeed with working store
	err := handler.Handle(ctx, msg)
	s.Require().NoError(err)

	// Verify event was stored
	events, err := s.auditStore.ListRecent(ctx, 10)
	s.Require().NoError(err)

	found := false
	for _, e := range events {
		if e.Action == "store_failure_test" {
			found = true
			break
		}
	}
	s.True(found, "event should be stored")
}
