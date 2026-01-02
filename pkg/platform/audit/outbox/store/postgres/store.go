package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"credo/pkg/platform/audit/outbox"

	"github.com/google/uuid"
)

// Store implements outbox.Store using PostgreSQL.
type Store struct {
	db *sql.DB
}

// New creates a new PostgreSQL outbox store.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// Append adds a new entry to the outbox table.
func (s *Store) Append(ctx context.Context, entry *outbox.Entry) error {
	query := `
		INSERT INTO outbox (id, aggregate_type, aggregate_id, event_type, payload, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := s.db.ExecContext(ctx, query,
		entry.ID,
		entry.AggregateType,
		entry.AggregateID,
		entry.EventType,
		entry.Payload,
		entry.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert outbox entry: %w", err)
	}
	return nil
}

// FetchUnprocessed returns up to limit entries that haven't been processed.
// Uses FOR UPDATE SKIP LOCKED to support concurrent workers without blocking.
func (s *Store) FetchUnprocessed(ctx context.Context, limit int) ([]*outbox.Entry, error) {
	query := `
		SELECT id, aggregate_type, aggregate_id, event_type, payload, created_at, processed_at
		FROM outbox
		WHERE processed_at IS NULL
		ORDER BY created_at ASC
		LIMIT $1
		FOR UPDATE SKIP LOCKED
	`
	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("fetch unprocessed entries: %w", err)
	}
	defer rows.Close()

	var entries []*outbox.Entry
	for rows.Next() {
		entry := &outbox.Entry{}
		err := rows.Scan(
			&entry.ID,
			&entry.AggregateType,
			&entry.AggregateID,
			&entry.EventType,
			&entry.Payload,
			&entry.CreatedAt,
			&entry.ProcessedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan outbox entry: %w", err)
		}
		entries = append(entries, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate outbox entries: %w", err)
	}

	return entries, nil
}

// MarkProcessed marks an entry as successfully published.
func (s *Store) MarkProcessed(ctx context.Context, id uuid.UUID, processedAt time.Time) error {
	query := `
		UPDATE outbox
		SET processed_at = $2
		WHERE id = $1 AND processed_at IS NULL
	`
	result, err := s.db.ExecContext(ctx, query, id, processedAt)
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
	query := `SELECT COUNT(*) FROM outbox WHERE processed_at IS NULL`
	var count int64
	err := s.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count pending entries: %w", err)
	}
	return count, nil
}

// DeleteProcessedBefore removes old processed entries.
func (s *Store) DeleteProcessedBefore(ctx context.Context, before time.Time) (int64, error) {
	query := `DELETE FROM outbox WHERE processed_at IS NOT NULL AND processed_at < $1`
	result, err := s.db.ExecContext(ctx, query, before)
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
	query := `
		INSERT INTO outbox (id, aggregate_type, aggregate_id, event_type, payload, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := tx.ExecContext(ctx, query,
		entry.ID,
		entry.AggregateType,
		entry.AggregateID,
		entry.EventType,
		entry.Payload,
		entry.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert outbox entry in tx: %w", err)
	}
	return nil
}

// BeginTx starts a new transaction.
func (s *Store) BeginTx(ctx context.Context) (*sql.Tx, error) {
	return s.db.BeginTx(ctx, nil)
}
