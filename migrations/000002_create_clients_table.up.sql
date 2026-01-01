-- Migration: Create clients table
-- OAuth 2.0 client registrations

CREATE TABLE IF NOT EXISTS clients (
    id                  UUID PRIMARY KEY,
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    name                VARCHAR(128) NOT NULL,
    oauth_client_id     VARCHAR(255) NOT NULL,
    client_secret_hash  VARCHAR(255),
    redirect_uris       JSONB NOT NULL DEFAULT '[]',
    allowed_grants      JSONB NOT NULL DEFAULT '[]',
    allowed_scopes      JSONB NOT NULL DEFAULT '[]',
    status              VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT clients_name_length CHECK (char_length(name) >= 1 AND char_length(name) <= 128),
    CONSTRAINT clients_oauth_client_id_not_empty CHECK (char_length(oauth_client_id) >= 1),
    CONSTRAINT clients_status_valid CHECK (status IN ('active', 'inactive')),
    CONSTRAINT clients_redirect_uris_not_empty CHECK (jsonb_array_length(redirect_uris) > 0),
    CONSTRAINT clients_allowed_grants_not_empty CHECK (jsonb_array_length(allowed_grants) > 0),
    CONSTRAINT clients_allowed_scopes_not_empty CHECK (jsonb_array_length(allowed_scopes) > 0)
);

CREATE UNIQUE INDEX idx_clients_oauth_client_id ON clients(oauth_client_id);
CREATE INDEX idx_clients_tenant_id ON clients(tenant_id);
CREATE INDEX idx_clients_status ON clients(status);

COMMENT ON TABLE clients IS 'OAuth 2.0 client registrations. ON DELETE RESTRICT prevents orphaning sessions.';
COMMENT ON COLUMN clients.client_secret_hash IS 'bcrypt hash. NULL indicates public client (SPA/mobile).';
COMMENT ON COLUMN clients.allowed_grants IS 'Array of grant types: authorization_code, refresh_token, client_credentials';
