-- Migration: Create audit_events table
-- Immutable audit log for compliance, security, and operations

CREATE TABLE IF NOT EXISTS audit_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category            VARCHAR(30) NOT NULL,
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tenant_id           UUID,
    user_id             UUID,
    subject             VARCHAR(255) NOT NULL DEFAULT '',
    action              VARCHAR(100) NOT NULL,
    purpose             VARCHAR(100) NOT NULL DEFAULT '',
    requesting_party    VARCHAR(255) NOT NULL DEFAULT '',
    decision            VARCHAR(50) NOT NULL DEFAULT '',
    reason              VARCHAR(500) NOT NULL DEFAULT '',
    email               VARCHAR(255) NOT NULL DEFAULT '',
    request_id          VARCHAR(255) NOT NULL DEFAULT '',
    actor_id            VARCHAR(255) NOT NULL DEFAULT '',
    metadata            JSONB NOT NULL DEFAULT '{}',

    CONSTRAINT audit_category_valid CHECK (category IN ('compliance', 'security', 'operations'))
);

CREATE INDEX idx_audit_events_user_id ON audit_events(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX idx_audit_events_tenant_id ON audit_events(tenant_id) WHERE tenant_id IS NOT NULL;
CREATE INDEX idx_audit_events_timestamp ON audit_events(timestamp DESC);
CREATE INDEX idx_audit_events_action ON audit_events(action);
CREATE INDEX idx_audit_events_category ON audit_events(category);
CREATE INDEX idx_audit_events_request_id ON audit_events(request_id) WHERE request_id != '';
CREATE INDEX idx_audit_events_category_timestamp ON audit_events(category, timestamp DESC);

COMMENT ON TABLE audit_events IS 'Immutable audit log. compliance=7yr retention, security=SIEM, operations=sampled.';
COMMENT ON COLUMN audit_events.category IS 'compliance | security | operations - drives retention/routing.';
COMMENT ON COLUMN audit_events.actor_id IS 'Admin who performed action when different from user_id.';
