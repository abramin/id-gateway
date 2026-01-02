package postgres

import (
	"context"
	"database/sql"
	"fmt"

	id "credo/pkg/domain"
	audit "credo/pkg/platform/audit"

	"github.com/google/uuid"
)

// Store implements audit.Store using PostgreSQL.
type Store struct {
	db *sql.DB
}

// New creates a new PostgreSQL audit store.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// Append inserts an audit event into the audit_events table.
func (s *Store) Append(ctx context.Context, event audit.Event) error {
	query := `
		INSERT INTO audit_events (
			id, category, timestamp, user_id, subject, action,
			purpose, requesting_party, decision, reason,
			email, request_id, actor_id
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	eventID := uuid.New()
	var userID *uuid.UUID
	if !event.UserID.IsNil() {
		uid := uuid.UUID(event.UserID)
		userID = &uid
	}

	_, err := s.db.ExecContext(ctx, query,
		eventID,
		string(event.Category),
		event.Timestamp,
		userID,
		event.Subject,
		event.Action,
		event.Purpose,
		event.RequestingParty,
		event.Decision,
		event.Reason,
		event.Email,
		event.RequestID,
		event.ActorID,
	)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

// AppendWithID inserts an audit event with a specific ID (for idempotent inserts).
func (s *Store) AppendWithID(ctx context.Context, eventID uuid.UUID, event audit.Event) error {
	query := `
		INSERT INTO audit_events (
			id, category, timestamp, user_id, subject, action,
			purpose, requesting_party, decision, reason,
			email, request_id, actor_id
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (id) DO NOTHING
	`

	var userID *uuid.UUID
	if !event.UserID.IsNil() {
		uid := uuid.UUID(event.UserID)
		userID = &uid
	}

	_, err := s.db.ExecContext(ctx, query,
		eventID,
		string(event.Category),
		event.Timestamp,
		userID,
		event.Subject,
		event.Action,
		event.Purpose,
		event.RequestingParty,
		event.Decision,
		event.Reason,
		event.Email,
		event.RequestID,
		event.ActorID,
	)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

// ListByUser returns events for a specific user.
func (s *Store) ListByUser(ctx context.Context, userID id.UserID) ([]audit.Event, error) {
	query := `
		SELECT category, timestamp, user_id, subject, action,
			   purpose, requesting_party, decision, reason,
			   email, request_id, actor_id
		FROM audit_events
		WHERE user_id = $1
		ORDER BY timestamp DESC
	`

	rows, err := s.db.QueryContext(ctx, query, uuid.UUID(userID))
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()

	return s.scanEvents(rows)
}

// ListAll returns all audit events (admin only).
func (s *Store) ListAll(ctx context.Context) ([]audit.Event, error) {
	query := `
		SELECT category, timestamp, user_id, subject, action,
			   purpose, requesting_party, decision, reason,
			   email, request_id, actor_id
		FROM audit_events
		ORDER BY timestamp DESC
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()

	return s.scanEvents(rows)
}

// ListRecent returns the N most recent events.
func (s *Store) ListRecent(ctx context.Context, limit int) ([]audit.Event, error) {
	query := `
		SELECT category, timestamp, user_id, subject, action,
			   purpose, requesting_party, decision, reason,
			   email, request_id, actor_id
		FROM audit_events
		ORDER BY timestamp DESC
		LIMIT $1
	`

	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()

	return s.scanEvents(rows)
}

// scanEvents scans multiple rows into audit.Event slice.
func (s *Store) scanEvents(rows *sql.Rows) ([]audit.Event, error) {
	var events []audit.Event

	for rows.Next() {
		var (
			category       string
			event          audit.Event
			userIDNullable *uuid.UUID
		)

		err := rows.Scan(
			&category,
			&event.Timestamp,
			&userIDNullable,
			&event.Subject,
			&event.Action,
			&event.Purpose,
			&event.RequestingParty,
			&event.Decision,
			&event.Reason,
			&event.Email,
			&event.RequestID,
			&event.ActorID,
		)
		if err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}

		event.Category = audit.EventCategory(category)
		if userIDNullable != nil {
			event.UserID = id.UserID(*userIDNullable)
		}

		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit events: %w", err)
	}

	return events, nil
}
