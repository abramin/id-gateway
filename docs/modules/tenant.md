# Tenant Module (PRD-026A)

## Summary

The tenant module is the system's "account manager." It creates tenants (customers) and the OAuth clients that act on their behalf, and it enforces the boundary that one tenant cannot see or use another tenant's data. It also provides the single, official way for Auth to map a `client_id` to a tenant during login and token flows.

## Why this matters (product view)

- Clear tenant boundaries make enterprise customers comfortable that their data and apps are isolated.
- Client registration enables partnerships and integrations without sharing internal IDs or user data.
- Admin-only endpoints let us control onboarding and reduce support risk during phase 0.
- Audit logs and metrics give operations and compliance teams visible signals during rollout.

## Scope and responsibilities

- Tenant lifecycle: create and read metadata for each customer account.
- Client lifecycle: create, read, update, and rotate secrets for apps that act on a tenant's behalf.
- Client -> tenant resolution for OAuth flows, so Auth never guesses tenant context.
- Tenant/client status enforcement to pause access cleanly when needed.

## Implemented in phase 0

- Service orchestration in `internal/tenant/service` backed by in-memory stores for demo use (fast to iterate, not durable).
- Admin HTTP handlers under `/admin` for tenants and clients (centralized onboarding control).
- Client secret generation + rotation with hashed storage (secrets shown once and never stored in plaintext).
- Input normalization/validation for names, redirect URIs, grants, and scopes (prevents misconfigured clients from breaking auth flows).
- Tenant isolation methods in service/store for tenant-scoped access paths (prevents cross-tenant leakage).
- Prometheus metric: `credo_tenants_created_total` (tracks onboarding volume).
- Audit logging hooks for tenant creation, client creation, and secret rotation (supports compliance and support investigations).

## Design decisions (why, tradeoffs, product impact)

- Domain invariants live in constructors (`models.NewTenant`, `models.NewClient`) rather than handlers. Benefit: rules are enforced everywhere (HTTP, tests, future jobs) so we avoid inconsistent behavior. Tradeoff: stricter failures earlier in workflows. Product impact: fewer edge-case support tickets from inconsistent tenant/client creation.
- Typed IDs (`id.TenantID`, `id.ClientID`) prevent cross-aggregate mixups and make signatures explicit. Benefit: safer code and fewer "wrong ID" bugs. Tradeoff: extra conversions in some layers. Product impact: reduced risk of a customer seeing the wrong data.
- Tenant name uniqueness is enforced case-insensitively in the store to avoid duplicate tenants. Benefit: "Acme" and "acme" are treated as the same account. Tradeoff: names that differ only by case are not allowed. Product impact: clearer billing/identity and less confusion for sales/support.
- Tenant isolation is implemented at the service/store layer (`GetClientForTenant`, `FindByTenantAndID`) to keep handlers thin. Benefit: the security boundary is enforced in one place. Tradeoff: callers must use the right service method. Product impact: safer multi-tenant behavior with less risk of accidental data leaks.
- Auth integrates through `ResolveClient(ctx, clientID)` rather than accessing tenant stores directly. Benefit: a single, audited path for client -> tenant resolution. Tradeoff: an extra call boundary between modules. Product impact: predictable behavior for auth, easier to evolve the system without breaking integrations.
- Internal UUIDs are separate from external OAuth `client_id`. Benefit: we can keep internal references stable even if a customer rotates or reissues an external client_id, and we avoid exposing internal identifiers. Tradeoff: two identifiers to manage and map. Product impact: safer client rotation and fewer breaking changes for customers.
- Public clients omit secrets and cannot use `client_credentials`. Benefit: reduces risk of secret leakage from mobile/SPAs. Tradeoff: some flows are not available to public clients. Product impact: clearer guidance for partners and fewer security incidents.

## Important implementation details (so what?)

- `CreateClient` generates a UUID `client_id` and a 32-byte base64 secret for confidential clients; only the hash is stored. This means secrets are never retrievable later, so partners must capture them at creation time.
- `UpdateClient` supports partial updates and optional secret rotation; `UpdatedAt` is refreshed on every update. This allows safe, incremental changes without breaking existing integrations.
- `ResolveClient` rejects inactive clients or tenants before returning to Auth. This provides a single kill switch for compromised clients or paused tenants.
- Redirect URIs must be HTTPS, with a localhost HTTP exception for development. This blocks token theft via insecure redirect endpoints while still allowing local testing.
- Allowed grants are whitelisted (`authorization_code`, `refresh_token`, `client_credentials`), and scopes are required. This prevents unsafe or unsupported OAuth flows from appearing in production.
- Tenant details include client and optional user counts (via `UserCounter`). This supports admin dashboards and usage reporting.

## Security features (what it protects)

- Secrets are never stored in plaintext; bcrypt hashing in `internal/tenant/secrets` protects against database leaks.
- Secret rotation emits an audit event and only returns cleartext on creation/rotation, limiting exposure windows.
- Redirect URI validation blocks non-HTTPS hosts (except localhost dev), reducing phishing and token interception risk.
- Public clients cannot use the `client_credentials` grant, preventing insecure server-to-server flows from untrusted apps.
- Admin endpoints are intended to be protected by `X-Admin-Token` middleware (platform admin auth) to gate access during phase 0.

## Observability

- Metric: `credo_tenants_created_total` for tenant creation volume and onboarding tracking.
- Metric: `credo_resolve_client_duration_seconds` histogram for OAuth critical path latency (p50/p95/p99 visibility).
- Audit log events for tenant creation, client creation, and secret rotation; includes `request_id` when available for support tracing.

## Integration points

- Auth service uses `ResolveClient` as the canonical client -> tenant lookup for OAuth flows, ensuring a single source of truth.
- HTTP endpoints (admin-only in phase 0):
  - `POST /admin/tenants`
  - `GET /admin/tenants/{id}`
  - `POST /admin/clients`
  - `GET /admin/clients/{id}`
  - `PUT /admin/clients/{id}`

## Known gaps / follow-ups

- Tenant-admin auth is not yet wired; handlers currently use platform-admin access paths with TODOs to switch to tenant-scoped methods. This limits self-service in phase 0.
- Persistence is demo-only; in-memory stores should be replaced with durable storage to support real onboarding and recovery.
- Consider argon2id for new installations: bcrypt is CPU-bound (~100ms at default cost). argon2id allows memory-hardness tuning for better resistance to GPU attacks. Migration requires bcrypt compatibility for existing hashes; only applicable to greenfield deployments or phased rollout with hash-on-verify upgrade.
