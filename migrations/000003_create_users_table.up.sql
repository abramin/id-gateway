-- Migration: Create users table
-- Authenticated end-users

CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    email           VARCHAR(255) NOT NULL,
    first_name      VARCHAR(255) NOT NULL DEFAULT '',
    last_name       VARCHAR(255) NOT NULL DEFAULT '',
    verified        BOOLEAN NOT NULL DEFAULT FALSE,
    status          VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT users_email_not_empty CHECK (char_length(email) >= 1),
    CONSTRAINT users_status_valid CHECK (status IN ('active', 'inactive'))
);

CREATE UNIQUE INDEX idx_users_tenant_email ON users(tenant_id, email);
CREATE INDEX idx_users_tenant_id ON users(tenant_id);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_status ON users(status);

COMMENT ON TABLE users IS 'Authenticated end-users. Email unique per tenant for isolation.';
