//go:build integration

package containers

import (
	"context"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/kafka"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
)

// KafkaContainer wraps a testcontainers Kafka instance.
type KafkaContainer struct {
	Container testcontainers.Container
	Brokers   string
}

// NewKafkaContainer starts a new Kafka (Redpanda) container.
// Uses Redpanda for faster startup and Kafka compatibility.
func NewKafkaContainer(t *testing.T) *KafkaContainer {
	t.Helper()

	ctx := context.Background()

	container, err := kafka.Run(ctx,
		"redpandadata/redpanda:latest",
		kafka.WithClusterID("test-cluster"),
	)
	if err != nil {
		t.Fatalf("failed to start kafka container: %v", err)
	}

	brokers, err := container.Brokers(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("failed to get kafka brokers: %v", err)
	}

	kc := &KafkaContainer{
		Container: container,
		Brokers:   brokers[0],
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = container.Terminate(ctx)
	})

	return kc
}

// CreateTopic creates a topic with the specified configuration.
func (k *KafkaContainer) CreateTopic(ctx context.Context, topic string, partitions int32, replicationFactor int16) error {
	client, err := kgo.NewClient(kgo.SeedBrokers(k.Brokers))
	if err != nil {
		return err
	}
	defer client.Close()

	admin := kadm.NewClient(client)

	_, err = admin.CreateTopics(ctx, partitions, replicationFactor, nil, topic)
	if err != nil {
		return err
	}

	return nil
}

// NewConsumer creates a franz-go consumer for verification in tests.
func (k *KafkaContainer) NewConsumer(ctx context.Context, groupID string, topics ...string) (*kgo.Client, error) {
	client, err := kgo.NewClient(
		kgo.SeedBrokers(k.Brokers),
		kgo.ConsumerGroup(groupID),
		kgo.ConsumeTopics(topics...),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
		kgo.DisableAutoCommit(),
	)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// WaitForMessage waits for a message matching the predicate within the timeout.
// Returns the matching message or nil if not found.
func (k *KafkaContainer) WaitForMessage(ctx context.Context, client *kgo.Client, timeout time.Duration, match func(*kgo.Record) bool) *kgo.Record {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			fetches := client.PollFetches(ctx)
			if fetches.IsClientClosed() {
				return nil
			}

			var found *kgo.Record
			fetches.EachRecord(func(r *kgo.Record) {
				if match(r) {
					found = r
				}
			})

			if found != nil {
				return found
			}
		}
	}
}
