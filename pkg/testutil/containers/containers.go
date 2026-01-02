//go:build integration

// Package containers provides testcontainers-based fixtures for integration tests.
// These containers are designed for reuse across test suites within a package.
package containers

import (
	"sync"
	"testing"
)

// Manager provides thread-safe access to shared containers.
// Containers are started on first request and reused across test suites.
type Manager struct {
	mu       sync.Mutex
	postgres *PostgresContainer
	kafka    *KafkaContainer
}

var (
	globalManager *Manager
	initOnce      sync.Once
)

// GetManager returns the singleton container manager.
// The manager is lazily initialized and shared across all tests in the same package.
func GetManager() *Manager {
	initOnce.Do(func() {
		globalManager = &Manager{}
	})
	return globalManager
}

// GetPostgres returns a Postgres container, starting it if necessary.
// The container persists across test suites in the same package.
func (m *Manager) GetPostgres(t *testing.T) *PostgresContainer {
	t.Helper()

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.postgres == nil {
		m.postgres = NewPostgresContainer(t)
	}
	return m.postgres
}

// GetKafka returns a Kafka container, starting it if necessary.
// The container persists across test suites in the same package.
func (m *Manager) GetKafka(t *testing.T) *KafkaContainer {
	t.Helper()

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.kafka == nil {
		m.kafka = NewKafkaContainer(t)
	}
	return m.kafka
}
