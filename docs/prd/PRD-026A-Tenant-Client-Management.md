# PRD-026A: Tenant & Client Management (MVP)

**Status:** Complete
**Priority:** P0 (Critical for Gateway Viability)
**Owner:** Engineering Team
**Dependencies:** PRD-001 (Authentication & Session Management), PRD-016 (Token Lifecycle & Revocation)
**Phase:** 0 → 1 (Foundation to Core Identity Plane)
**Last Updated:** 2025-12-24

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

---

## FR-4.5 Auth ↔ Tenant Integration (Concrete)

### Purpose

Define the **explicit integration boundary** between the Auth module and the Tenant & Client module.
Auth must enforce tenant-scoped identity rules without owning tenant data.
Tenant must remain the source of truth for clients and tenants.

This section specifies:

- what Auth must change
- what Tenant must expose
- how data flows, step by step

No transport is assumed. In-process calls are used for MVP.

---

## FR-4.5.1 Ownership & Boundaries

**Tenant module owns:**

- Tenant lifecycle
- Client lifecycle
- Client → Tenant resolution
- Client and tenant status

**Auth module owns:**

- User lifecycle
- Sessions, authorization codes, tokens
- Enforcement of user status
- Token claims

**Hard rule:**
Auth MUST NOT access tenant/client stores directly.
Tenant MUST NOT access auth user stores directly.

---

## FR-4.5.2 Integration Port (Required)

Auth defines a port. Tenant implements it.

```go
// internal/auth/ports/client_resolver.go
type ClientResolver interface {
    ResolveClient(ctx context.Context, clientID string) (*Client, *Tenant, error)
}
```

This is injected into `AuthService`.

```go
type AuthService struct {
    users          UserStore
    sessions       SessionStore
    codes          AuthorizationCodeStore
    refreshTokens  RefreshTokenStore
    clientResolver ClientResolver
}
```

---

## FR-4.5.3 Tenant Responsibilities (What to Add)

Tenant service MUST expose:

```go
// internal/tenant/service/service.go
func (s *Service) ResolveClient(
    ctx context.Context,
    clientID string,
) (*models.Client, *models.Tenant, error)
```

Behavior:

1. Lookup client by `client_id`
2. Enforce `client.status == active`
3. Lookup tenant by `client.tenant_id`
4. Enforce `tenant.status == active`
5. Return `(client, tenant)`

Errors (RFC 6749 compliant):

- unknown client → 400 Bad Request with `invalid_client`
- inactive client → 400 Bad Request with `invalid_client`
- inactive tenant → 400 Bad Request with `access_denied`

**Note:** These errors occur during OAuth flows (authorize/token) and follow RFC 6749 error response format.

This method is the **only supported way** for auth to derive tenant context.

---

## FR-4.5.4 Auth Changes (Where FR-5 Is Enforced)

### Authorize flow (signup + login)

Pseudocode inside `AuthService.Authorize`:

```go
client, tenant, err := s.clientResolver.ResolveClient(ctx, req.ClientID)
if err != nil {
    return nil, err
}

user, err := s.users.FindByTenantAndEmail(ctx, tenant.ID, req.Email)
if err == NotFound {
    user = NewUser(tenant.ID, req.Email)
    s.users.Save(ctx, user)
}

if user.Status != Active {
    return nil, accessDenied("user inactive")
}

// proceed with session + auth code creation
```

**Key points:**

- tenant_id is derived, never accepted from request
- user lookup is `(tenant_id, email)`
- inactive users fail before code issuance

This fully implements **FR-5 Creation + Lookup + Status**.

---

### Token exchange

Pseudocode inside `AuthService.Token`:

```go
code := s.codes.FindByCode(req.Code)
session := s.sessions.FindByID(code.SessionID)

// resolve client again to enforce status at token time
client, tenant := s.clientResolver.ResolveClient(ctx, session.ClientID)

if session.UserStatus != Active {
    return nil, accessDenied("user inactive")
}

// issue tokens with tenant_id + client_id claims
```

Tenant resolution happens again to prevent:

- client disabled after authorize
- tenant suspended mid-flow

---

## FR-4.5.5 User Store Changes (Auth)

User store MUST support tenant-scoped lookup.

```go
FindByTenantAndEmail(ctx, tenantID, email)
```

Auth enforces uniqueness on `(tenant_id, email)`.

Tenant module never queries users directly.
At most, it consumes a **read-only counter interface**.

---

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

> **Implementation Note:** Scope enforcement (validating `RequestedScope ⊆ client.AllowedScopes`) is implemented in `internal/auth/service/authorize.go`.

### FR-8: Security & Isolation Controls

- **Redirect URI Matching:** Exact match against registered URIs (string comparison after normalization).
- **Audit Events:** `client.created`, `client.updated`, `client.secret_rotated`, `tenant.created`, `user.created` with actor/tenant context.
- **Cross-Tenant Protections:** No user lookup without tenant context; queries scoped by tenant for all user/client reads.

### FR-9: Backward Compatibility

- Existing auth endpoints remain but now require `client_id`. A default bootstrap tenant/client may be seeded for demo environments to avoid breaking existing tests.

### FR-10: Issuer Management (RFC 8414 Compliance)

Per RFC 8414 (Authorization Server Metadata) and OpenID Connect Core 1.0, each tenant has a unique issuer URL.

**Issuer Format:**

```
{base_url}/tenants/{tenant_id}
```

Example: `https://auth.credo.io/tenants/550e8400-e29b-41d4-a716-446655440000`

**Token Claims:**

- The `iss` claim in access tokens and ID tokens uses the per-tenant issuer format
- The `tenant_id` is also included as a custom claim in access tokens for client convenience
- Downstream services can derive tenant from the issuer URL or use the explicit claim

**Implementation Notes:**

- Issuer base URL configured via `JWT_ISSUER_BASE_URL` environment variable
- Default: `http://localhost:8080` for development
- JWT service dynamically builds issuer using `{base_url}/tenants/{tenant_id}`
- Global signing key used across all tenants (per-tenant keys are future work)

**Future Enhancements (Out of Scope):**

- Per-tenant signing keys for key isolation
- OIDC Discovery per tenant: `GET /tenants/{tenant_id}/.well-known/openid-configuration`
- JWKS per tenant: `GET /tenants/{tenant_id}/.well-known/jwks.json`
- Per-tenant audience values

**References:**

- RFC 8414: Authorization Server Metadata
- OpenID Connect Core 1.0, Section 2 (Issuer Identifier)

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
- **Token Signing:** HS256 only for MVP; any header algo mismatch (including `none`) is rejected as invalid without leaking detail.
- **Tenant/Client Suspension Effects:** On tenant or client suspension, auth/refresh/code issuance and reuse are denied; tie into PRD-016 revocation to invalidate outstanding codes/tokens.
- **Telemetry:** Audit events for tenant/client/user creation and secret rotation; emit security alerts on repeated invalid client_id attempts.

---

## 8. Non-Functional Requirements

- **Migration/Seed:** Provide bootstrap migration to create an initial tenant and client for demo/E2E tests to avoid breaking existing flows.
- **Observability:** Log tenant_id/client_id in structured logs for auth/admin endpoints (without leaking secrets).
- **Latency:** Tenant/client resolution adds <5ms p95 with indexed lookups.
- **Resilience:** If tenant inactive, all auth requests for its clients return `access_denied` without leaking tenant existence.

---

## 9. Acceptance Criteria

- [x] A tenant can be created and retrieved via admin API.
- [x] A client can be registered under a tenant with redirect URI validation.
- [x] OAuth authorization fails with `invalid_client` when client_id is unknown or inactive.
- [x] Users created during signup are scoped to the tenant associated with the client.
- [x] Access and ID tokens include `tenant_id` and `client_id` claims.
- [x] Client secret rotation updates the stored hash and old secrets fail authentication.
- [x] Audit events emitted for tenant/client/user creation and secret rotation.
- [x] All admin endpoints reject unauthenticated requests with 401 Unauthorized.
- [ ] Authenticated requests without sufficient admin capability are rejected with 403 Forbidden. _(Deferred to [PRD-026](PRD-026-Admin-Dashboard-Operations-UI.md) role-based admin access)_
- [x] Platform admin access allows tenant creation and retrieval.
- [x] Tenant admin access allows client management only within the caller's tenant.
- [x] Authorization checks are enforced in the service layer and cannot be bypassed by handler misuse.
- [x] Secrets are hashed with argon2id/bcrypt and are never retrievable after creation/rotation responses.
- [x] Redirect URIs must exactly match registered normalized URIs; wildcards and mismatched hosts/schemes/ports are rejected.
- [x] Tokens with mismatched or `none` alg headers are rejected as invalid.

---

## 10. Open Questions / Future Extensions

- Should we support **organization/teams** within a tenant in Phase 2? (Out of scope now.)
- Do we need **client credentials grant** for machine-to-machine apps in MVP? If not, restrict to `authorization_code` and `refresh_token`.
- How should **tenant-level settings** (password policies, MFA requirement) be configured? Potential follow-up PRD.
- Should we harden key custody with **per-tenant keys and HSM-backed signing**, including JWKS rotation windows and backward-compatible key rollover?

---

### 11. Architectural Integration Notes

- Tenant and client resolution is **owned by this module**.
- A canonical service method (e.g. `ResolveClient(client_id) → {client, tenant}`) MUST be used by downstream modules to derive tenant context from OAuth requests.
- Admin handlers MAY continue to operate without implicit tenant scoping, but tenant-scoped service methods MUST exist for tenant-admin and auth flows.
- Other modules MUST NOT re-implement client → tenant resolution logic.
- Authentication and token issuance flows will be updated in a follow-up PRD to consume this abstraction.

---

## 12. Features Identified During Implementation

The following features were implemented beyond original PRD scope:

1. **Client Store Secondary Indexes**: `byCode` map for O(1) OAuth client_id lookup (`internal/tenant/store/client/`)
2. **Intent-revealing Domain Methods**: `IsActive()`, `IsConfidential()` on Client model
3. **Atomic Find-or-Create**: Mutex-protected tenant-scoped user creation (`FindOrCreateByTenantAndEmail`)
4. **Scoped Service Methods**: `GetClientForTenant()`, `UpdateClientForTenant()` ready for tenant admin enforcement

## Known Gaps

None - all MVP requirements implemented. The following is deferred to Phase 6:

1. **Tenant Admin Role-Based Access**: Fine-grained tenant admin authorization deferred to [PRD-026: Admin Dashboard & Operations UI](./PRD-026-Admin-Dashboard-Operations-UI.md)

---

## Revision History

| Version | Date       | Author           | Changes                                                                |
| ------- | ---------- | ---------------- | ---------------------------------------------------------------------- |
| 1.0     | 2025-12-13 | Product Team     | Initial PRD                                                            |
| 1.1     | 2025-12-14 | Engineering Team | Add notes on integration with other modules                            |
| 1.2     | 2025-12-17 | Engineering Team | RFC compliance: Added explicit HTTP status codes (400) for error cases |
| 1.3     | 2025-12-17 | Engineering Team | RFC 8414 compliance: Added FR-10 Issuer Management                     |
|         |            |                  | - Per-tenant issuer format: `{base_url}/tenants/{tenant_id}`           |
|         |            |                  | - Updated FR-7 Claims & Scopes to include issuer format                |
|         |            |                  | - Documented future work: OIDC discovery and JWKS per tenant           |
| 1.4     | 2025-12-24 | Engineering Team | Status verification: scope enforcement confirmed implemented           |
|         |            |                  | - Updated FR-7 implementation note                                     |
|         |            |                  | - Cleared Known Gaps (scope enforcement done)                          |
