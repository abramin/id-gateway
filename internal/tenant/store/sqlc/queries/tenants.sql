-- name: CreateTenant :exec
INSERT INTO tenants (id, name, status, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5);

-- name: GetTenantByID :one
SELECT id, name, status, created_at, updated_at
FROM tenants
WHERE id = $1;

-- name: GetTenantByName :one
SELECT id, name, status, created_at, updated_at
FROM tenants
WHERE lower(name) = lower($1);

-- name: CountTenants :one
SELECT COUNT(*) FROM tenants;

-- name: UpdateTenant :execresult
UPDATE tenants
SET name = $2, status = $3, updated_at = $4
WHERE id = $1;

-- name: GetTenantForUpdate :one
SELECT id, name, status, created_at, updated_at
FROM tenants
WHERE id = $1
FOR UPDATE;
