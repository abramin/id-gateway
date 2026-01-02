package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"credo/internal/platform/kafka/consumer"
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

	// Unmarshal audit event from message value
	var event audit.Event
	if err := json.Unmarshal(msg.Value, &event); err != nil {
		h.logger.Error("failed to unmarshal audit event",
			"event_id", eventID,
			"error", err,
		)
		// Return nil to commit the offset - malformed messages should not block processing
		return nil
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
