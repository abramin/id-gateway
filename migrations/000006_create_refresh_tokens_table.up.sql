-- Migration: Create refresh_tokens table
-- Long-lived refresh tokens with rotation support

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id                  UUID PRIMARY KEY,
    token               VARCHAR(255) NOT NULL,
    session_id          UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    expires_at          TIMESTAMPTZ NOT NULL,
    used                BOOLEAN NOT NULL DEFAULT FALSE,
    last_refreshed_at   TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT refresh_token_not_empty CHECK (char_length(token) >= 1)
);

CREATE UNIQUE INDEX idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX idx_refresh_tokens_session_id ON refresh_tokens(session_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_used ON refresh_tokens(used);
CREATE INDEX idx_refresh_tokens_session_active ON refresh_tokens(session_id, used, expires_at)
    WHERE used = FALSE;

COMMENT ON TABLE refresh_tokens IS 'Long-lived (30 days) refresh tokens with rotation support.';
COMMENT ON COLUMN refresh_tokens.used IS 'Set TRUE on rotation. Replay indicates potential theft.';
