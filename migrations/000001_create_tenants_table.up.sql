-- Migration: Create tenants table
-- Multi-tenant organization entities

CREATE TABLE IF NOT EXISTS tenants (
    id              UUID PRIMARY KEY,
    name            VARCHAR(128) NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT tenants_name_length CHECK (char_length(name) >= 1 AND char_length(name) <= 128),
    CONSTRAINT tenants_status_valid CHECK (status IN ('active', 'inactive'))
);

CREATE UNIQUE INDEX idx_tenants_name ON tenants(name);
CREATE INDEX idx_tenants_status ON tenants(status);

COMMENT ON TABLE tenants IS 'Multi-tenant organization entities. Inactive tenant blocks all OAuth flows.';
COMMENT ON COLUMN tenants.status IS 'Lifecycle: active <-> inactive. Enforced in service layer.';
