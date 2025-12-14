# PRD-026A: Tenant & Client Management (MVP)

**Status:** Proposed (Not Started)
**Priority:** P0 (Critical for Gateway Viability)
**Owner:** Engineering Team
**Dependencies:** PRD-001 (Authentication & Session Management), PRD-016 (Token Lifecycle & Revocation)
**Phase:** 0 → 1 (Foundation to Core Identity Plane)
**Last Updated:** 2025-12-12

---

## 1. Overview

### Problem Statement

Credo currently supports OAuth-style authentication flows but lacks the concept of **tenants** (isolated identity boundaries) and **client applications** (relying parties). Without these primitives:

- There is no isolation between different client applications
- Users cannot belong to a logical organization boundary
- OAuth flows are not scoped to a registered client or tenant
- Tokens do not express which tenant/client they belong to
- Credo effectively behaves like a single hardcoded application, not a multi-tenant gateway

Auth0 and similar providers make tenant + application registration first-class. Credo needs a minimal equivalent to operate as a real identity gateway.

### Goals (MVP Scope)

- Allow a **tenant** to exist as an isolated identity boundary
- Allow a tenant to register one or more **OAuth clients**
- Require **client_id** on OAuth flows and resolve the tenant via client lookup
- Ensure **users are created and resolved within a tenant** during signup/login
- Issue tokens containing **tenant_id** and **client_id** claims to support downstream authorization

### Non-Goals (MVP)

- Organizations/teams inside a tenant
- Social login
- Marketplace, billing, or plans
- Fine-grained RBAC beyond scopes
- IdP-initiated SSO or cross-tenant federation

---

## 2. User Stories

**As a platform administrator**
**I want to** create a tenant and bootstrap its first admin user
**So that** new client applications can onboard safely

**As a tenant admin**
**I want to** register OAuth clients with redirect URIs and allowed grants
**So that** my applications can use Credo for login

**As a client application**
**I want to** initiate OAuth flows with my registered client_id
**So that** I can authenticate users for my tenant

**As a user**
**I want to** sign up or log in within my tenant boundary
**So that** my account is isolated from other tenants

**As a security engineer**
**I want to** ensure tokens contain tenant and client claims
**So that** downstream services can enforce isolation

---

## 3. Functional Requirements

### FR-1: Tenant Creation (Admin-Only)

- **Endpoint:** `POST /admin/tenants`
- **Behavior:** Creates a tenant with a unique name and returns `tenant_id`.
- **Validation:** Name required, max 128 chars, must be unique (case-insensitive).
- **Side Effects:** Audit log entry `tenant.created` with actor admin id.

### FR-2: Tenant Retrieval (Admin-Only)

- **Endpoint:** `GET /admin/tenants/{id}`
- **Behavior:** Returns tenant metadata (id, name, created_at) and summary counts (users, clients) for admin UI.
- **Error Cases:** `404` if tenant not found; `403` if caller lacks admin scope.

### FR-3: Client Registration (Tenant Admin)

- **Endpoint:** `POST /admin/clients`
- **Behavior:** Registers a client under a tenant. Generates `client_id` (UUID/ULID) and `client_secret` for confidential clients.
- **Required Fields:** `tenant_id`, `name`, `redirect_uris[]`, `allowed_grants[]`.
- **Validation:**
  - `redirect_uris` must be HTTPS (except `http://localhost` for dev)
  - `allowed_grants` subset of `authorization_code`, `refresh_token`, `client_credentials` (if supported)
  - `client_id` globally unique
- **Secrets:** `client_secret` is hashed at rest. Public clients omit secret.

### FR-4: Client Retrieval & Update (Tenant Admin)

- **Endpoints:** `GET /admin/clients/{id}`, `PUT /admin/clients/{id}`
- **Behavior:** Fetch or update client metadata, redirect URIs, and allowed grants/scopes. Secret rotation via update regenerates secret and invalidates previous hash.
- **Constraints:** Tenant admins can only manage clients within their tenant.

### FR-5: Tenant-Scoped User Lifecycle

- **Creation:** Users created during signup are stored with `tenant_id` derived from the client.
- **Lookup:** Login resolves user by `tenant_id + email` to avoid cross-tenant collisions.
- **Status:** Users have `status` (active, inactive). Inactive users cannot obtain tokens.

### FR-6: OAuth Flow Tenant Resolution

- **Authorization Request:** Existing `/oauth/authorize` requires `client_id`; Credo resolves client → tenant before rendering signup/login UI.
- **Token Exchange:** `/oauth/token` validates `client_id`/secret (if confidential) and issues tokens containing `tenant_id` + `client_id` claims.
- **Error Handling:** Unknown or inactive client returns `invalid_client`; tenant-inactive returns `access_denied`.

### FR-7: Claims & Scopes

- **ID/Access Token Claims:** Must include `tenant_id`, `client_id`, `sub`, `scope`, `exp`, `iat`, `iss`, `aud`.
- **Scope Enforcement:** Requested scopes must be subset of client `allowed_scopes`; reject otherwise.

### FR-8: Security & Isolation Controls

- **Redirect URI Matching:** Exact match against registered URIs (string comparison after normalization).
- **Audit Events:** `client.created`, `client.updated`, `client.secret_rotated`, `tenant.created`, `user.created` with actor/tenant context.
- **Cross-Tenant Protections:** No user lookup without tenant context; queries scoped by tenant for all user/client reads.

### FR-9: Backward Compatibility

- Existing auth endpoints remain but now require `client_id`. A default bootstrap tenant/client may be seeded for demo environments to avoid breaking existing tests.

---

## 4. Data Model (Minimal)

### Tenant

- `id` (uuid, primary key)
- `name` (string, unique, required)
- `created_at` (timestamp)

### Client

- `id` (uuid, primary key)
- `tenant_id` (uuid, fk → tenant.id)
- `name` (string)
- `client_id` (string, globally unique)
- `client_secret_hash` (string, nullable for public clients)
- `redirect_uris` (string array)
- `allowed_grants` (string array)
- `allowed_scopes` (string array)
- `created_at` (timestamp)
- `updated_at` (timestamp)
- `status` (active, inactive)

### User

- `id` (uuid, primary key)
- `tenant_id` (uuid, fk → tenant.id)
- `email` (string, unique per tenant)
- `password_hash` (string)
- `status` (active, inactive)
- `created_at` (timestamp)
- `updated_at` (timestamp)

### Constraints

- `client.tenant_id` must reference an existing tenant
- `user.tenant_id` must reference an existing tenant
- `client_id` globally unique; `email` unique per tenant
- Soft-delete not in scope for MVP

---

## 5. API Surface (MVP)

### Tenant Management (Admin Only)

- `POST /admin/tenants`
  - **Body:** `{ "name": "Acme" }`
  - **Responses:** `201` with `{ "tenant_id": "..." }`; `409` on duplicate name
- `GET /admin/tenants/{id}`
  - **Responses:** `200` with tenant metadata and counts; `404` if missing

### Client Management (Tenant Admin)

- `POST /admin/clients`
  - **Body:** `{ "tenant_id": "...", "name": "Web", "redirect_uris": ["https://app.example.com/callback"], "allowed_grants": ["authorization_code"], "allowed_scopes": ["openid", "profile"] }`
  - **Responses:** `201` with `client_id`, `client_secret` (once), and metadata; `400` on validation failure
- `GET /admin/clients/{id}`
  - **Responses:** `200` with client metadata; `404` if missing or tenant mismatch
- `PUT /admin/clients/{id}`
  - **Body:** Partial update for name, redirect URIs, allowed grants/scopes; optional `rotate_secret: true`
  - **Responses:** `200` with updated metadata; `401/403` for unauthorized tenant admins

### Auth Flow Integration (Existing Endpoints Extended)

- `/oauth/authorize`
  - **Required:** `client_id`, `redirect_uri`, `response_type=code`, `scope`
  - **Process:** Resolve client → tenant → render hosted signup/login for that tenant
- `/oauth/token`
  - **Required:** `grant_type`, `client_id`, `code` (for auth code), `redirect_uri`; `client_secret` if confidential
  - **Output:** Access + ID tokens with tenant/client claims; optional refresh token based on allowed grants

---

## 6. Flows (Concrete)

### Signup Flow

1. Client redirects user to `/oauth/authorize?client_id=...&redirect_uri=...&scope=openid`.
2. Credo resolves `client_id` → `tenant_id`; validates redirect URI + grants.
3. Hosted signup UI captures email/password and creates `User` under `tenant_id`.
4. Authorization code is issued and returned via redirect to client.
5. Client exchanges code at `/oauth/token` to receive tokens containing `tenant_id` + `client_id` claims.

### Login Flow

1. Client initiates `/oauth/authorize` with registered `client_id`.
2. Credo resolves tenant, prompts for credentials.
3. User lookup uses `tenant_id + email`; password validated.
4. Code issued, token exchange returns tokens scoped to tenant + client.

### Client Secret Rotation

1. Tenant admin calls `PUT /admin/clients/{id}` with `rotate_secret: true`.
2. Credo generates new secret, stores hash, invalidates previous hash, returns new secret once.
3. Audit event `client.secret_rotated` emitted.

---

## Authorization Model (MVP)

- All `/admin/*` endpoints **MUST require authentication**.
- Authentication is performed using **access tokens issued by PRD-001 (Authentication & Session Management)**.
- Requests without a valid access token MUST be rejected with `401 Unauthorized`.

### **Authorization Semantics (Coarse-Grained)**

- Two coarse actor capabilities are recognized for MVP:

  - **Platform Admin**: may create and view tenants.
  - **Tenant Admin**: may create, view, and update clients within their tenant.

- The mechanism by which an actor is identified as a platform admin or tenant admin is intentionally minimal for MVP and may be implemented via:

  - a boolean claim in the access token (e.g. `is_platform_admin`, `is_tenant_admin`), or
  - a coarse actor type claim (e.g. `actor_type = platform_admin | tenant_admin`).

### **Tenant Boundary Enforcement**

- Tenant admins MUST only be authorized to manage clients belonging to their own tenant.
- Platform admins MAY access tenants and clients across all tenants.
- All authorization checks are enforced in the **service layer**, not in HTTP handlers.

### **Out of Scope**

- Fine-grained RBAC or policy engines
- Dynamic permission assignment
- Delegated administration or organization hierarchies

These capabilities may be introduced in a future PRD once tenant and client primitives are stable.

–––

## 7. Security Considerations

- **Secrets:** `client_secret` stored hashed with strong KDF (argon2id/bcrypt). Never returned after creation/rotation response.
- **Redirect URIs:** Exact string match after normalization; no wildcard subdomains.
- **Tenant Isolation:** All user/client queries filter by `tenant_id`; no cross-tenant joins for auth paths.
- **Rate Limits:** Reuse PRD-017 defaults for admin endpoints; protect tenant creation and client registration.
- **Token Claims:** Include `tenant_id` and `client_id`; downstream services must validate issuer/audience and tenant match.
- **Telemetry:** Audit events for tenant/client/user creation and secret rotation; emit security alerts on repeated invalid client_id attempts.

---

## 8. Non-Functional Requirements

- **Migration/Seed:** Provide bootstrap migration to create an initial tenant and client for demo/E2E tests to avoid breaking existing flows.
- **Observability:** Log tenant_id/client_id in structured logs for auth/admin endpoints (without leaking secrets).
- **Latency:** Tenant/client resolution adds <5ms p95 with indexed lookups.
- **Resilience:** If tenant inactive, all auth requests for its clients return `access_denied` without leaking tenant existence.

---

## 9. Acceptance Criteria

- [ ]A tenant can be created and retrieved via admin API.
- [ ]A client can be registered under a tenant with redirect URI validation.
- [ ]OAuth authorization fails with `invalid_client` when client_id is unknown or inactive.
- [ ]Users created during signup are scoped to the tenant associated with the client.
- [ ]Access and ID tokens include `tenant_id` and `client_id` claims.
- [ ]Client secret rotation updates the stored hash and old secrets fail authentication.
- [ ]Audit events emitted for tenant/client/user creation and secret rotation.
- [ ] All admin endpoints reject unauthenticated requests with 401 Unauthorized.
- [ ] Authenticated requests without sufficient admin capability are rejected with 403 Forbidden.
- [ ] Platform admin access allows tenant creation and retrieval.
- [ ] Tenant admin access allows client management only within the caller’s tenant.
- [ ] Authorization checks are enforced in the service layer and cannot be bypassed by handler misuse.

---

## 10. Open Questions / Future Extensions

- Should we support **organization/teams** within a tenant in Phase 2? (Out of scope now.)
- Do we need **client credentials grant** for machine-to-machine apps in MVP? If not, restrict to `authorization_code` and `refresh_token`.
- How should **tenant-level settings** (password policies, MFA requirement) be configured? Potential follow-up PRD.

---

### 11. Architectural Integration Notes

- Tenant and client resolution is **owned by this module**.
- A canonical service method (e.g. `ResolveClient(client_id) → {client, tenant}`) MUST be used by downstream modules to derive tenant context from OAuth requests.
- Admin handlers MAY continue to operate without implicit tenant scoping, but tenant-scoped service methods MUST exist for tenant-admin and auth flows.
- Other modules MUST NOT re-implement client → tenant resolution logic.
- Authentication and token issuance flows will be updated in a follow-up PRD to consume this abstraction.

---

## Revision History

| Version | Date       | Author           | Changes                                     |
| ------- | ---------- | ---------------- | ------------------------------------------- |
| 1.0     | 2025-12-13 | Product Team     | Initial PRD                                 |
| 1.1     | 2025-12-14 | Engineering Team | Add notes on integration with other modules |
