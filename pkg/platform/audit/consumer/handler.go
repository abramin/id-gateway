package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"credo/internal/platform/kafka/consumer"
	id "credo/pkg/domain"
	audit "credo/pkg/platform/audit"
	auditpostgres "credo/pkg/platform/audit/store/postgres"

	"github.com/google/uuid"
)

// Handler processes audit events from Kafka and writes them to PostgreSQL.
// It implements consumer.Handler for use with the Kafka consumer.
type Handler struct {
	store  *auditpostgres.Store
	logger *slog.Logger
}

// NewHandler creates a new audit event consumer handler.
func NewHandler(store *auditpostgres.Store, logger *slog.Logger) *Handler {
	return &Handler{
		store:  store,
		logger: logger,
	}
}

// kafkaPayload matches the JSON structure produced by the outbox store.
type kafkaPayload struct {
	ID              string `json:"ID"`
	Category        string `json:"Category"`
	Timestamp       string `json:"Timestamp"`
	UserID          string `json:"UserID"`
	Subject         string `json:"Subject"`
	Action          string `json:"Action"`
	Purpose         string `json:"Purpose"`
	RequestingParty string `json:"RequestingParty"`
	Decision        string `json:"Decision"`
	Reason          string `json:"Reason"`
	Email           string `json:"Email"`
	RequestID       string `json:"RequestID"`
	ActorID         string `json:"ActorID"`
}

// Handle processes a single Kafka message containing an audit event.
// It performs idempotent insert using the message key as the event ID.
func (h *Handler) Handle(ctx context.Context, msg *consumer.Message) error {
	// Parse event ID from message key
	eventID, err := uuid.Parse(string(msg.Key))
	if err != nil {
		h.logger.Error("failed to parse event ID from message key",
			"key", string(msg.Key),
			"error", err,
		)
		// Return nil to commit the offset - malformed messages should not block processing
		return nil
	}

	// Unmarshal into intermediate struct that matches the JSON format
	var payload kafkaPayload
	if err := json.Unmarshal(msg.Value, &payload); err != nil {
		h.logger.Error("failed to unmarshal audit payload",
			"event_id", eventID,
			"error", err,
		)
		return nil
	}

	// Convert to audit.Event
	event := audit.Event{
		Category:        audit.EventCategory(payload.Category),
		Subject:         payload.Subject,
		Action:          payload.Action,
		Purpose:         payload.Purpose,
		RequestingParty: payload.RequestingParty,
		Decision:        payload.Decision,
		Reason:          payload.Reason,
		Email:           payload.Email,
		RequestID:       payload.RequestID,
		ActorID:         payload.ActorID,
	}

	// Parse timestamp
	if payload.Timestamp != "" {
		if ts, err := time.Parse(time.RFC3339Nano, payload.Timestamp); err == nil {
			event.Timestamp = ts
		}
	}

	// Parse UserID
	if payload.UserID != "" {
		if uid, err := uuid.Parse(payload.UserID); err == nil {
			event.UserID = id.UserID(uid)
		}
	}

	// Default category if empty
	if event.Category == "" {
		event.Category = audit.CategoryOperations
	}

	// Log the event being processed
	h.logger.Debug("processing audit event",
		"event_id", eventID,
		"action", event.Action,
		"user_id", event.UserID,
	)

	// Idempotent insert using event ID
	if err := h.store.AppendWithID(ctx, eventID, event); err != nil {
		h.logger.Error("failed to store audit event",
			"event_id", eventID,
			"action", event.Action,
			"error", err,
		)
		// Return error to prevent commit - message will be redelivered
		return fmt.Errorf("store audit event: %w", err)
	}

	h.logger.Debug("stored audit event",
		"event_id", eventID,
		"action", event.Action,
	)

	return nil
}
