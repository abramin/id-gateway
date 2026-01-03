-- name: UpsertUser :exec
INSERT INTO users (id, tenant_id, email, first_name, last_name, verified, status)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (id) DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    email = EXCLUDED.email,
    first_name = EXCLUDED.first_name,
    last_name = EXCLUDED.last_name,
    verified = EXCLUDED.verified,
    status = EXCLUDED.status,
    updated_at = NOW();

-- name: GetUserByID :one
SELECT id, tenant_id, email, first_name, last_name, verified, status
FROM users
WHERE id = $1;

-- name: GetUserByEmail :one
SELECT id, tenant_id, email, first_name, last_name, verified, status
FROM users
WHERE email = $1
ORDER BY created_at ASC
LIMIT 1;

-- name: InsertUserIfNotExists :exec
INSERT INTO users (id, tenant_id, email, first_name, last_name, verified, status)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (tenant_id, email) DO NOTHING;

-- name: GetUserByTenantEmail :one
SELECT id, tenant_id, email, first_name, last_name, verified, status
FROM users
WHERE tenant_id = $1 AND email = $2;

-- name: DeleteUserByID :execresult
DELETE FROM users WHERE id = $1;

-- name: ListUsers :many
SELECT id, tenant_id, email, first_name, last_name, verified, status
FROM users;

-- name: CountUsersByTenant :one
SELECT COUNT(*) FROM users WHERE tenant_id = $1;
