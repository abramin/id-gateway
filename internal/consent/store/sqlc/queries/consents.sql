-- name: InsertConsent :one
INSERT INTO consents (id, user_id, purpose, granted_at, expires_at, revoked_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (user_id, purpose) DO NOTHING
RETURNING id;

-- name: GetConsentByScope :one
SELECT id, user_id, purpose, granted_at, expires_at, revoked_at
FROM consents
WHERE user_id = $1 AND purpose = $2;

-- name: GetConsentByScopeForUpdate :one
SELECT id, user_id, purpose, granted_at, expires_at, revoked_at
FROM consents
WHERE user_id = $1 AND purpose = $2
FOR UPDATE;

-- name: ListConsentsByUser :many
SELECT id, user_id, purpose, granted_at, expires_at, revoked_at
FROM consents
WHERE user_id = $1;

-- name: ListConsentsByUserAndPurpose :many
SELECT id, user_id, purpose, granted_at, expires_at, revoked_at
FROM consents
WHERE user_id = $1 AND purpose = $2;

-- name: UpdateConsent :execresult
UPDATE consents
SET granted_at = $2, expires_at = $3, revoked_at = $4
WHERE id = $1 AND user_id = $5 AND purpose = $6;

-- name: RevokeAllConsentsByUser :execresult
UPDATE consents
SET revoked_at = $2
WHERE user_id = $1
  AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at >= $2);

-- name: DeleteConsentsByUser :exec
DELETE FROM consents WHERE user_id = $1;
