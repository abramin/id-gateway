-- Migration: Create Postgres-backed cache and rate limit tables

CREATE TABLE IF NOT EXISTS citizen_cache (
    national_id VARCHAR(20) NOT NULL,
    full_name TEXT NOT NULL,
    date_of_birth TEXT NOT NULL,
    address TEXT NOT NULL,
    valid BOOLEAN NOT NULL,
    source TEXT NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL,
    regulated BOOLEAN NOT NULL DEFAULT FALSE,

    PRIMARY KEY (national_id, regulated)
);

CREATE INDEX idx_citizen_cache_national_id ON citizen_cache (national_id);
CREATE INDEX idx_citizen_cache_checked_at ON citizen_cache (checked_at);

CREATE TABLE IF NOT EXISTS sanctions_cache (
    national_id VARCHAR(20) PRIMARY KEY,
    listed BOOLEAN NOT NULL,
    source TEXT NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_sanctions_cache_checked_at ON sanctions_cache (checked_at);

CREATE TABLE IF NOT EXISTS vc_credentials (
    id VARCHAR(64) PRIMARY KEY,
    type VARCHAR(64) NOT NULL,
    subject_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issuer VARCHAR(255) NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    claims JSONB NOT NULL
);

CREATE INDEX idx_vc_credentials_subject_type ON vc_credentials (subject_id, type, issued_at DESC);

CREATE TABLE IF NOT EXISTS token_revocations (
    jti VARCHAR(255) PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_token_revocations_expires_at ON token_revocations (expires_at);

CREATE TABLE IF NOT EXISTS rate_limit_events (
    id BIGSERIAL PRIMARY KEY,
    key TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    cost INT NOT NULL,
    window_seconds INT NOT NULL
);

CREATE INDEX idx_rate_limit_events_key_time ON rate_limit_events (key, occurred_at);

CREATE TABLE IF NOT EXISTS rate_limit_allowlist (
    id VARCHAR(64) PRIMARY KEY,
    entry_type VARCHAR(20) NOT NULL,
    identifier VARCHAR(255) NOT NULL,
    reason TEXT NOT NULL,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX idx_rate_limit_allowlist_key ON rate_limit_allowlist (entry_type, identifier);
CREATE INDEX idx_rate_limit_allowlist_expires ON rate_limit_allowlist (expires_at);

CREATE TABLE IF NOT EXISTS auth_lockouts (
    identifier VARCHAR(255) PRIMARY KEY,
    failure_count INT NOT NULL,
    daily_failures INT NOT NULL,
    locked_until TIMESTAMPTZ,
    last_failure_at TIMESTAMPTZ NOT NULL,
    requires_captcha BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_auth_lockouts_last_failure_at ON auth_lockouts (last_failure_at);

CREATE TABLE IF NOT EXISTS global_throttle (
    bucket_type VARCHAR(20) PRIMARY KEY,
    bucket_start TIMESTAMPTZ NOT NULL,
    count INT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_name_ci ON tenants (lower(name));
