package outbox

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Store defines the outbox persistence operations.
// Implementations must be safe for concurrent use.
type Store interface {
	// Append adds a new entry to the outbox.
	// This should be called within the same transaction as the business operation.
	Append(ctx context.Context, entry *Entry) error

	// FetchUnprocessed returns up to limit entries that haven't been processed.
	// Entries are ordered by created_at ASC (oldest first).
	// Implementations should use row-level locking (e.g., FOR UPDATE SKIP LOCKED)
	// to support concurrent workers.
	FetchUnprocessed(ctx context.Context, limit int) ([]*Entry, error)

	// MarkProcessed marks an entry as successfully published to Kafka.
	MarkProcessed(ctx context.Context, id uuid.UUID, processedAt time.Time) error

	// CountPending returns the number of unprocessed entries.
	// Used for metrics and health monitoring.
	CountPending(ctx context.Context) (int64, error)

	// DeleteProcessedBefore removes old processed entries for cleanup.
	// Returns the number of entries deleted.
	DeleteProcessedBefore(ctx context.Context, before time.Time) (int64, error)
}
