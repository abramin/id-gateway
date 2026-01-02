package kafka

import "time"

// ProducerConfig holds configuration for the Kafka producer.
type ProducerConfig struct {
	Brokers         string
	Acks            string
	Retries         int
	DeliveryTimeout time.Duration
}

// ConsumerConfig holds configuration for the Kafka consumer.
type ConsumerConfig struct {
	Brokers       string
	GroupID       string
	Topics        []string
	AutoOffsetReset string
}

// DefaultProducerConfig returns sensible defaults for production use.
func DefaultProducerConfig() ProducerConfig {
	return ProducerConfig{
		Acks:            "all",
		Retries:         3,
		DeliveryTimeout: 30 * time.Second,
	}
}

// DefaultConsumerConfig returns sensible defaults for production use.
func DefaultConsumerConfig() ConsumerConfig {
	return ConsumerConfig{
		AutoOffsetReset: "earliest",
	}
}
