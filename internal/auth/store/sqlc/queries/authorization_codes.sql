-- name: CreateAuthorizationCode :exec
INSERT INTO authorization_codes (id, code, session_id, redirect_uri, expires_at, used, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: GetAuthorizationCodeByCode :one
SELECT id, code, session_id, redirect_uri, expires_at, used, created_at
FROM authorization_codes
WHERE code = $1;

-- name: MarkAuthorizationCodeUsed :execresult
UPDATE authorization_codes SET used = TRUE WHERE code = $1;

-- name: DeleteExpiredAuthorizationCodes :execresult
DELETE FROM authorization_codes WHERE expires_at < $1;

-- name: GetAuthorizationCodeForUpdate :one
SELECT id, code, session_id, redirect_uri, expires_at, used, created_at
FROM authorization_codes
WHERE code = $1
FOR UPDATE;

-- name: UpdateAuthorizationCodeUsed :exec
UPDATE authorization_codes SET used = $2 WHERE code = $1;
