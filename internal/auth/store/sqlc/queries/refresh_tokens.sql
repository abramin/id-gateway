-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (id, token, session_id, expires_at, used, last_refreshed_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: GetRefreshTokenByToken :one
SELECT id, token, session_id, expires_at, used, last_refreshed_at, created_at
FROM refresh_tokens
WHERE token = $1;

-- name: GetRefreshTokenBySession :one
SELECT id, token, session_id, expires_at, used, last_refreshed_at, created_at
FROM refresh_tokens
WHERE session_id = $1 AND used = FALSE AND expires_at > $2
ORDER BY created_at DESC
LIMIT 1;

-- name: DeleteRefreshTokensBySession :execresult
DELETE FROM refresh_tokens WHERE session_id = $1;

-- name: DeleteExpiredRefreshTokens :execresult
DELETE FROM refresh_tokens WHERE expires_at < $1;

-- name: DeleteUsedRefreshTokens :execresult
DELETE FROM refresh_tokens WHERE used = TRUE;

-- name: GetRefreshTokenForUpdate :one
SELECT id, token, session_id, expires_at, used, last_refreshed_at, created_at
FROM refresh_tokens
WHERE token = $1
FOR UPDATE;

-- name: UpdateRefreshTokenUsage :exec
UPDATE refresh_tokens
SET used = $2, last_refreshed_at = $3
WHERE token = $1;
