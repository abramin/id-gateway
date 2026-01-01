-- Migration: Create authorization_codes table
-- Short-lived OAuth authorization codes

CREATE TABLE IF NOT EXISTS authorization_codes (
    id              UUID PRIMARY KEY,
    code            VARCHAR(255) NOT NULL,
    session_id      UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    redirect_uri    VARCHAR(2048) NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    used            BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT authz_code_not_empty CHECK (char_length(code) >= 1),
    CONSTRAINT authz_redirect_uri_not_empty CHECK (char_length(redirect_uri) >= 1)
);

CREATE UNIQUE INDEX idx_authorization_codes_code ON authorization_codes(code);
CREATE INDEX idx_authorization_codes_session_id ON authorization_codes(session_id);
CREATE INDEX idx_authorization_codes_expires_at ON authorization_codes(expires_at);
CREATE INDEX idx_authorization_codes_used ON authorization_codes(used);

COMMENT ON TABLE authorization_codes IS 'Short-lived (10min) OAuth authorization codes. Child of session.';
COMMENT ON COLUMN authorization_codes.code IS 'Format: authz_<random>. Single-use for replay prevention.';
