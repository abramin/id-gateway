-- vc_credentials stores issued verifiable credentials
CREATE TABLE IF NOT EXISTS vc_credentials (
    id VARCHAR(100) PRIMARY KEY,
    type VARCHAR(50) NOT NULL,
    subject_id UUID NOT NULL,
    issuer VARCHAR(100) NOT NULL,
    issued_at TIMESTAMP WITH TIME ZONE NOT NULL,
    claims JSONB,
    is_over_18 BOOLEAN,
    verified_via VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Add columns if table existed without them (idempotent)
ALTER TABLE vc_credentials ADD COLUMN IF NOT EXISTS is_over_18 BOOLEAN;
ALTER TABLE vc_credentials ADD COLUMN IF NOT EXISTS verified_via VARCHAR(100);
ALTER TABLE vc_credentials ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();

-- Index for looking up credentials by subject and type
CREATE INDEX IF NOT EXISTS idx_vc_credentials_subject_type ON vc_credentials(subject_id, type);
