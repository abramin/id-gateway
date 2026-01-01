-- Migration: Create outbox table
-- Transactional outbox for reliable event publishing to Kafka/Redpanda

CREATE TABLE IF NOT EXISTS outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregate_type  VARCHAR(50) NOT NULL,
    aggregate_id    VARCHAR(255) NOT NULL,
    event_type      VARCHAR(100) NOT NULL,
    payload         JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at    TIMESTAMPTZ,

    CONSTRAINT outbox_aggregate_type_not_empty CHECK (char_length(aggregate_type) >= 1),
    CONSTRAINT outbox_aggregate_id_not_empty CHECK (char_length(aggregate_id) >= 1),
    CONSTRAINT outbox_event_type_not_empty CHECK (char_length(event_type) >= 1)
);

CREATE INDEX idx_outbox_unprocessed ON outbox(created_at)
    WHERE processed_at IS NULL;
CREATE INDEX idx_outbox_aggregate ON outbox(aggregate_type, aggregate_id);
CREATE INDEX idx_outbox_event_type ON outbox(event_type);
CREATE INDEX idx_outbox_processed_at ON outbox(processed_at)
    WHERE processed_at IS NOT NULL;

COMMENT ON TABLE outbox IS 'Transactional outbox for reliable event publishing to Kafka/Redpanda.';
COMMENT ON COLUMN outbox.processed_at IS 'NULL = pending, non-NULL = published. Enables at-least-once delivery.';
COMMENT ON COLUMN outbox.aggregate_type IS 'e.g., user, session, consent, tenant, client';
