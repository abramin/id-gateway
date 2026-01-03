-- name: UpsertTokenRevocation :exec
INSERT INTO token_revocations (jti, expires_at)
VALUES ($1, $2)
ON CONFLICT (jti) DO UPDATE SET
    expires_at = EXCLUDED.expires_at;

-- name: GetTokenRevocationExpiresAt :one
SELECT expires_at FROM token_revocations WHERE jti = $1;

-- name: UpsertTokenRevocations :exec
INSERT INTO token_revocations (jti, expires_at)
SELECT unnest($1::text[]), $2
ON CONFLICT (jti) DO UPDATE SET
    expires_at = EXCLUDED.expires_at;
