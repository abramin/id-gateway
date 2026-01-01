-- Migration: Create sessions table
-- Authentication sessions with device binding

CREATE TABLE IF NOT EXISTS sessions (
    id                      UUID PRIMARY KEY,
    user_id                 UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id               UUID NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    requested_scope         JSONB NOT NULL DEFAULT '[]',
    status                  VARCHAR(30) NOT NULL DEFAULT 'pending_consent',
    last_refreshed_at       TIMESTAMPTZ,
    last_access_token_jti   VARCHAR(255) NOT NULL DEFAULT '',
    device_id               VARCHAR(255) NOT NULL DEFAULT '',
    device_fingerprint_hash VARCHAR(255) NOT NULL DEFAULT '',
    device_display_name     VARCHAR(255) NOT NULL DEFAULT '',
    approximate_location    VARCHAR(255) NOT NULL DEFAULT '',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at              TIMESTAMPTZ NOT NULL,
    last_seen_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at              TIMESTAMPTZ,

    CONSTRAINT sessions_status_valid CHECK (status IN ('pending_consent', 'active', 'revoked')),
    CONSTRAINT sessions_scopes_not_empty CHECK (jsonb_array_length(requested_scope) > 0),
    CONSTRAINT sessions_expires_after_created CHECK (expires_at > created_at)
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_client_id ON sessions(client_id);
CREATE INDEX idx_sessions_tenant_id ON sessions(tenant_id);
CREATE INDEX idx_sessions_status ON sessions(status);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sessions_device_id ON sessions(device_id) WHERE device_id != '';

COMMENT ON TABLE sessions IS 'Authentication sessions. CASCADE on user delete. RESTRICT on client/tenant.';
COMMENT ON COLUMN sessions.status IS 'Lifecycle: pending_consent -> active -> revoked. Revoked is terminal.';
COMMENT ON COLUMN sessions.last_access_token_jti IS 'Latest access token JTI for revocation tracking.';
