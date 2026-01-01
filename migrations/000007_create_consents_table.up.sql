-- Migration: Create consents table
-- Purpose-based user consent records

CREATE TABLE IF NOT EXISTS consents (
    id              UUID PRIMARY KEY,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose         VARCHAR(50) NOT NULL,
    granted_at      TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,

    CONSTRAINT consents_purpose_valid CHECK (purpose IN ('login', 'registry_check', 'vc_issuance', 'decision_evaluation'))
);

CREATE UNIQUE INDEX idx_consents_user_purpose ON consents(user_id, purpose);
CREATE INDEX idx_consents_user_id ON consents(user_id);
CREATE INDEX idx_consents_purpose ON consents(purpose);
CREATE INDEX idx_consents_active ON consents(user_id)
    WHERE revoked_at IS NULL;

COMMENT ON TABLE consents IS 'Purpose-based user consent records. Unique per (user_id, purpose).';
COMMENT ON COLUMN consents.purpose IS 'login | registry_check | vc_issuance | decision_evaluation';
