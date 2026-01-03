-- name: CreateSession :exec
INSERT INTO sessions (
    id, user_id, client_id, tenant_id, requested_scope, status,
    last_refreshed_at, last_access_token_jti, device_id, device_fingerprint_hash,
    device_display_name, approximate_location, created_at, expires_at, last_seen_at, revoked_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16);

-- name: GetSessionByID :one
SELECT id, user_id, client_id, tenant_id, requested_scope, status,
    last_refreshed_at, last_access_token_jti, device_id, device_fingerprint_hash,
    device_display_name, approximate_location, created_at, expires_at, last_seen_at, revoked_at
FROM sessions
WHERE id = $1;

-- name: ListSessionsByUser :many
SELECT id, user_id, client_id, tenant_id, requested_scope, status,
    last_refreshed_at, last_access_token_jti, device_id, device_fingerprint_hash,
    device_display_name, approximate_location, created_at, expires_at, last_seen_at, revoked_at
FROM sessions
WHERE user_id = $1;

-- name: UpdateSession :execresult
UPDATE sessions
SET user_id = $2,
    client_id = $3,
    tenant_id = $4,
    requested_scope = $5,
    status = $6,
    last_refreshed_at = $7,
    last_access_token_jti = $8,
    device_id = $9,
    device_fingerprint_hash = $10,
    device_display_name = $11,
    approximate_location = $12,
    created_at = $13,
    expires_at = $14,
    last_seen_at = $15,
    revoked_at = $16
WHERE id = $1;

-- name: DeleteSessionsByUser :execresult
DELETE FROM sessions WHERE user_id = $1;

-- name: GetSessionForUpdate :one
SELECT id, user_id, client_id, tenant_id, requested_scope, status,
    last_refreshed_at, last_access_token_jti, device_id, device_fingerprint_hash,
    device_display_name, approximate_location, created_at, expires_at, last_seen_at, revoked_at
FROM sessions
WHERE id = $1
FOR UPDATE;

-- name: DeleteExpiredSessions :execresult
DELETE FROM sessions WHERE expires_at < $1;

-- name: ListSessions :many
SELECT id, user_id, client_id, tenant_id, requested_scope, status,
    last_refreshed_at, last_access_token_jti, device_id, device_fingerprint_hash,
    device_display_name, approximate_location, created_at, expires_at, last_seen_at, revoked_at
FROM sessions;
