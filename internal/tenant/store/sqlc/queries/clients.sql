-- name: CreateClient :exec
INSERT INTO clients (
    id, tenant_id, name, oauth_client_id, client_secret_hash, redirect_uris,
    allowed_grants, allowed_scopes, status, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- name: UpdateClient :execresult
UPDATE clients
SET name = $2,
    oauth_client_id = $3,
    client_secret_hash = $4,
    redirect_uris = $5,
    allowed_grants = $6,
    allowed_scopes = $7,
    status = $8,
    updated_at = $9
WHERE id = $1;

-- name: GetClientByID :one
SELECT id, tenant_id, name, oauth_client_id, client_secret_hash, redirect_uris,
    allowed_grants, allowed_scopes, status, created_at, updated_at
FROM clients
WHERE id = $1;

-- name: GetClientByTenantAndID :one
SELECT id, tenant_id, name, oauth_client_id, client_secret_hash, redirect_uris,
    allowed_grants, allowed_scopes, status, created_at, updated_at
FROM clients
WHERE id = $1 AND tenant_id = $2;

-- name: GetClientByOAuthClientID :one
SELECT id, tenant_id, name, oauth_client_id, client_secret_hash, redirect_uris,
    allowed_grants, allowed_scopes, status, created_at, updated_at
FROM clients
WHERE oauth_client_id = $1;

-- name: CountClientsByTenant :one
SELECT COUNT(*) FROM clients WHERE tenant_id = $1;

-- name: GetClientForUpdate :one
SELECT id, tenant_id, name, oauth_client_id, client_secret_hash, redirect_uris,
    allowed_grants, allowed_scopes, status, created_at, updated_at
FROM clients
WHERE id = $1
FOR UPDATE;
