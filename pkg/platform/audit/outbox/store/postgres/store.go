package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"credo/pkg/platform/audit/outbox"
	outboxsqlc "credo/pkg/platform/audit/outbox/store/postgres/sqlc"

	"github.com/google/uuid"
)

// Store implements outbox.Store using PostgreSQL.
type Store struct {
	db      *sql.DB
	queries *outboxsqlc.Queries
}

// New creates a new PostgreSQL outbox store.
func New(db *sql.DB) *Store {
	return &Store{
		db:      db,
		queries: outboxsqlc.New(db),
	}
}

// Append adds a new entry to the outbox table.
func (s *Store) Append(ctx context.Context, entry *outbox.Entry) error {
	err := s.queries.InsertOutboxEntry(ctx, outboxsqlc.InsertOutboxEntryParams{
		ID:            entry.ID,
		AggregateType: entry.AggregateType,
		AggregateID:   entry.AggregateID,
		EventType:     entry.EventType,
		Payload:       json.RawMessage(entry.Payload),
		CreatedAt:     entry.CreatedAt,
	})
	if err != nil {
		return fmt.Errorf("insert outbox entry: %w", err)
	}
	return nil
}

// FetchUnprocessed returns up to limit entries that haven't been processed.
// Uses FOR UPDATE SKIP LOCKED to support concurrent workers without blocking.
func (s *Store) FetchUnprocessed(ctx context.Context, limit int) ([]*outbox.Entry, error) {
	if limit <= 0 {
		return nil, nil
	}
	// Cap to reasonable batch size (gosec G115: prevent int->int32 overflow)
	const maxBatch = 1000
	if limit > maxBatch {
		limit = maxBatch
	}
	rows, err := s.queries.ListUnprocessedOutboxEntries(ctx, int32(limit)) // #nosec G115
	if err != nil {
		return nil, fmt.Errorf("fetch unprocessed entries: %w", err)
	}
	entries := make([]*outbox.Entry, 0, len(rows))
	for _, row := range rows {
		entries = append(entries, toOutboxEntry(row))
	}
	return entries, nil
}

// MarkProcessed marks an entry as successfully published.
func (s *Store) MarkProcessed(ctx context.Context, id uuid.UUID, processedAt time.Time) error {
	result, err := s.queries.MarkOutboxEntryProcessed(ctx, outboxsqlc.MarkOutboxEntryProcessedParams{
		ID:          id,
		ProcessedAt: sql.NullTime{Time: processedAt, Valid: true},
	})
	if err != nil {
		return fmt.Errorf("mark outbox entry processed: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("outbox entry not found or already processed: %s", id)
	}

	return nil
}

// CountPending returns the number of unprocessed entries.
func (s *Store) CountPending(ctx context.Context) (int64, error) {
	count, err := s.queries.CountPendingOutboxEntries(ctx)
	if err != nil {
		return 0, fmt.Errorf("count pending entries: %w", err)
	}
	return count, nil
}

// DeleteProcessedBefore removes old processed entries.
func (s *Store) DeleteProcessedBefore(ctx context.Context, before time.Time) (int64, error) {
	result, err := s.queries.DeleteProcessedOutboxEntriesBefore(ctx, sql.NullTime{Time: before, Valid: true})
	if err != nil {
		return 0, fmt.Errorf("delete processed entries: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("get rows affected: %w", err)
	}

	return rowsAffected, nil
}

// AppendTx adds a new entry to the outbox table within a transaction.
// Use this when you want to include the outbox write in an existing transaction.
func (s *Store) AppendTx(ctx context.Context, tx *sql.Tx, entry *outbox.Entry) error {
	qtx := s.queries.WithTx(tx)
	if err := qtx.InsertOutboxEntry(ctx, outboxsqlc.InsertOutboxEntryParams{
		ID:            entry.ID,
		AggregateType: entry.AggregateType,
		AggregateID:   entry.AggregateID,
		EventType:     entry.EventType,
		Payload:       json.RawMessage(entry.Payload),
		CreatedAt:     entry.CreatedAt,
	}); err != nil {
		return fmt.Errorf("insert outbox entry in tx: %w", err)
	}
	return nil
}

// BeginTx starts a new transaction.
func (s *Store) BeginTx(ctx context.Context) (*sql.Tx, error) {
	return s.db.BeginTx(ctx, nil)
}

func toOutboxEntry(row outboxsqlc.Outbox) *outbox.Entry {
	entry := &outbox.Entry{
		ID:            row.ID,
		AggregateType: row.AggregateType,
		AggregateID:   row.AggregateID,
		EventType:     row.EventType,
		Payload:       []byte(row.Payload),
		CreatedAt:     row.CreatedAt,
	}
	if row.ProcessedAt.Valid {
		entry.ProcessedAt = &row.ProcessedAt.Time
	}
	return entry
}
