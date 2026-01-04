package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	id "credo/pkg/domain"
	audit "credo/pkg/platform/audit"
	auditsqlc "credo/pkg/platform/audit/store/postgres/sqlc"
	txcontext "credo/pkg/platform/tx"

	"github.com/google/uuid"
)

// Store implements audit.Store using the transactional outbox pattern.
// Events are written to the outbox table and published to Kafka by the outbox worker.
// Kafka is the source of truth for audit events.
type Store struct {
	db      *sql.DB
	queries *auditsqlc.Queries
}

// New creates a new PostgreSQL audit store that writes to the outbox.
func New(db *sql.DB) *Store {
	return &Store{
		db:      db,
		queries: auditsqlc.New(db),
	}
}

func (s *Store) queriesFor(ctx context.Context) *auditsqlc.Queries {
	if tx, ok := txcontext.From(ctx); ok {
		return s.queries.WithTx(tx)
	}
	return s.queries
}

// outboxPayload is the JSON structure published to Kafka.
// Field names match audit.Event for proper deserialization by the consumer.
type outboxPayload struct {
	ID              string `json:"ID"`
	Category        string `json:"Category"`
	Timestamp       string `json:"Timestamp"`
	UserID          string `json:"UserID,omitempty"`
	Subject         string `json:"Subject"`
	Action          string `json:"Action"`
	Purpose         string `json:"Purpose,omitempty"`
	RequestingParty string `json:"RequestingParty,omitempty"`
	Decision        string `json:"Decision,omitempty"`
	Reason          string `json:"Reason,omitempty"`
	Email           string `json:"Email,omitempty"`
	RequestID       string `json:"RequestID,omitempty"`
	ActorID         string `json:"ActorID,omitempty"`
}

// Append writes an audit event to the outbox table for Kafka publishing.
func (s *Store) Append(ctx context.Context, event audit.Event) error {
	eventID := uuid.New()

	// Always derive category from action - eventCategories map is the source of truth
	category := audit.AuditEvent(event.Action).Category()

	// Build JSON payload for Kafka
	payload := outboxPayload{
		ID:              eventID.String(),
		Category:        string(category),
		Timestamp:       event.Timestamp.Format(time.RFC3339Nano),
		Subject:         event.Subject,
		Action:          event.Action,
		Purpose:         event.Purpose,
		RequestingParty: event.RequestingParty,
		Decision:        event.Decision,
		Reason:          event.Reason,
		Email:           event.Email,
		RequestID:       event.RequestID,
		ActorID:         event.ActorID,
	}
	if !event.UserID.IsNil() {
		payload.UserID = uuid.UUID(event.UserID).String()
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal audit payload: %w", err)
	}

	// Determine aggregate type and ID
	aggregateType := "audit"
	aggregateID := eventID.String()
	if !event.UserID.IsNil() {
		aggregateType = "user"
		aggregateID = uuid.UUID(event.UserID).String()
	}

	err = s.queriesFor(ctx).InsertOutboxEntry(ctx, auditsqlc.InsertOutboxEntryParams{
		ID:            uuid.New(), // outbox entry ID
		AggregateType: aggregateType,
		AggregateID:   aggregateID,
		EventType:     event.Action,
		Payload:       json.RawMessage(payloadBytes),
		CreatedAt:     time.Now(),
	})
	if err != nil {
		return fmt.Errorf("insert outbox entry: %w", err)
	}
	return nil
}

// AppendWithID inserts an audit event into the audit_events table with a specific ID.
// Used by the Kafka consumer to materialize events for querying.
// This is idempotent - duplicate inserts are ignored via ON CONFLICT DO NOTHING.
func (s *Store) AppendWithID(ctx context.Context, eventID uuid.UUID, event audit.Event) error {
	var userID uuid.NullUUID
	if !event.UserID.IsNil() {
		userID = uuid.NullUUID{UUID: uuid.UUID(event.UserID), Valid: true}
	}

	if err := s.queries.InsertAuditEvent(ctx, auditsqlc.InsertAuditEventParams{
		ID:              eventID,
		Category:        string(event.Category),
		Timestamp:       event.Timestamp,
		UserID:          userID,
		Subject:         event.Subject,
		Action:          event.Action,
		Purpose:         event.Purpose,
		RequestingParty: event.RequestingParty,
		Decision:        event.Decision,
		Reason:          event.Reason,
		Email:           event.Email,
		RequestID:       event.RequestID,
		ActorID:         event.ActorID,
	}); err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

// ListByUser returns events for a specific user.
func (s *Store) ListByUser(ctx context.Context, userID id.UserID) ([]audit.Event, error) {
	rows, err := s.queries.ListAuditEventsByUser(ctx, uuid.NullUUID{UUID: uuid.UUID(userID), Valid: true})
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	return mapAuditEvents(toAuditEventRowsFromByUser(rows)), nil
}

// ListAll returns all audit events (admin only).
func (s *Store) ListAll(ctx context.Context) ([]audit.Event, error) {
	rows, err := s.queries.ListAuditEvents(ctx)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	return mapAuditEvents(toAuditEventRowsFromAll(rows)), nil
}

// ListRecent returns the N most recent events.
func (s *Store) ListRecent(ctx context.Context, limit int) ([]audit.Event, error) {
	limit = max(1000, limit)
	rows, err := s.queries.ListRecentAuditEvents(ctx, int32(limit)) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	return mapAuditEvents(toAuditEventRowsFromRecent(rows)), nil
}

type auditEventRow struct {
	Timestamp       time.Time
	UserID          uuid.NullUUID
	Category        string
	Subject         string
	Action          string
	Purpose         string
	RequestingParty string
	Decision        string
	Reason          string
	Email           string
	RequestID       string
	ActorID         string
}

func mapAuditEvents(rows []auditEventRow) []audit.Event {
	events := make([]audit.Event, 0, len(rows))
	for _, row := range rows {
		events = append(events, toAuditEvent(row))
	}
	return events
}

func toAuditEventRowsFromByUser(rows []auditsqlc.ListAuditEventsByUserRow) []auditEventRow {
	events := make([]auditEventRow, 0, len(rows))
	for _, row := range rows {
		events = append(events, auditEventRow{
			Category:        row.Category,
			Timestamp:       row.Timestamp,
			UserID:          row.UserID,
			Subject:         row.Subject,
			Action:          row.Action,
			Purpose:         row.Purpose,
			RequestingParty: row.RequestingParty,
			Decision:        row.Decision,
			Reason:          row.Reason,
			Email:           row.Email,
			RequestID:       row.RequestID,
			ActorID:         row.ActorID,
		})
	}
	return events
}

func toAuditEventRowsFromAll(rows []auditsqlc.ListAuditEventsRow) []auditEventRow {
	events := make([]auditEventRow, 0, len(rows))
	for _, row := range rows {
		events = append(events, auditEventRow{
			Category:        row.Category,
			Timestamp:       row.Timestamp,
			UserID:          row.UserID,
			Subject:         row.Subject,
			Action:          row.Action,
			Purpose:         row.Purpose,
			RequestingParty: row.RequestingParty,
			Decision:        row.Decision,
			Reason:          row.Reason,
			Email:           row.Email,
			RequestID:       row.RequestID,
			ActorID:         row.ActorID,
		})
	}
	return events
}

func toAuditEventRowsFromRecent(rows []auditsqlc.ListRecentAuditEventsRow) []auditEventRow {
	events := make([]auditEventRow, 0, len(rows))
	for _, row := range rows {
		events = append(events, auditEventRow{
			Category:        row.Category,
			Timestamp:       row.Timestamp,
			UserID:          row.UserID,
			Subject:         row.Subject,
			Action:          row.Action,
			Purpose:         row.Purpose,
			RequestingParty: row.RequestingParty,
			Decision:        row.Decision,
			Reason:          row.Reason,
			Email:           row.Email,
			RequestID:       row.RequestID,
			ActorID:         row.ActorID,
		})
	}
	return events
}

func toAuditEvent(row auditEventRow) audit.Event {
	event := audit.Event{
		Category:        audit.EventCategory(row.Category),
		Timestamp:       row.Timestamp,
		Subject:         row.Subject,
		Action:          row.Action,
		Purpose:         row.Purpose,
		RequestingParty: row.RequestingParty,
		Decision:        row.Decision,
		Reason:          row.Reason,
		Email:           row.Email,
		RequestID:       row.RequestID,
		ActorID:         row.ActorID,
	}
	if row.UserID.Valid {
		event.UserID = id.UserID(row.UserID.UUID)
	}
	return event
}
