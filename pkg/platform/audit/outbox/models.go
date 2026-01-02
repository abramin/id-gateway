package outbox

import (
	"time"

	"github.com/google/uuid"
)

// Entry represents a pending event in the outbox table.
// It follows the transactional outbox pattern for reliable event publishing.
type Entry struct {
	ID            uuid.UUID
	AggregateType string     // e.g., "user", "session", "consent", "tenant", "client"
	AggregateID   string     // e.g., user ID, session ID
	EventType     string     // e.g., "user_created", "consent_granted"
	Payload       []byte     // JSON-encoded audit.Event
	CreatedAt     time.Time  // When the entry was created
	ProcessedAt   *time.Time // NULL = pending, non-NULL = published to Kafka
}

// IsPending returns true if this entry has not been processed yet.
func (e *Entry) IsPending() bool {
	return e.ProcessedAt == nil
}

// NewEntry creates a new outbox entry with a generated UUID.
func NewEntry(aggregateType, aggregateID, eventType string, payload []byte) *Entry {
	return &Entry{
		ID:            uuid.New(),
		AggregateType: aggregateType,
		AggregateID:   aggregateID,
		EventType:     eventType,
		Payload:       payload,
		CreatedAt:     time.Now(),
	}
}
