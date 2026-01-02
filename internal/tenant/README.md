# Tenant Module

Multi-tenancy and OAuth 2.0 client management for the Credo platform.

---

## Domain Design

### Bounded Context

**Context:** `internal/tenant`

**Purpose:** Multi-tenant partition management and OAuth client registration:
- Tenants represent logical partitions for isolation
- Clients are OAuth 2.0 registrations under a tenant
- Client resolution is the critical choke point for OAuth flows
- Tenant deactivation blocks all OAuth flows for all its clients

### Ubiquitous Language

| Domain Term        | Code Location                                |
| ------------------ | -------------------------------------------- |
| **Tenant**         | `models.Tenant`                              |
| **Client**         | `models.Client`                              |
| **TenantDetails**  | `readmodels.TenantDetails` (read model)      |
| **Create Tenant**  | `service.TenantService.CreateTenant()`       |
| **Create Client**  | `service.ClientService.CreateClient()`       |
| **Resolve Client** | `service.ClientService.ResolveClient()`      |
| **Secret Rotation**| `service.ClientService.RotateClientSecret()` |

---

## Aggregates and Invariants

### Tenant Aggregate (Root)

**Entity:** `Tenant`
- Represents a logical partition for multi-tenancy
- Fields: ID (TenantID), Name (unique), Status (Active/Inactive), timestamps

**Invariants:**
- Name must be unique (case-insensitive)
- Name must be 1-128 characters
- Cannot deactivate already-inactive tenant
- Cannot reactivate already-active tenant

**Intent-revealing methods:**
- `IsActive()` - status is active
- `Deactivate(now)` - transition to inactive
- `Reactivate(now)` - transition to active

### Client Aggregate (Root)

**Entity:** `Client`
- OAuth 2.0 client registration under a tenant
- Fields: ID, TenantID, Name, OAuthClientID, ClientSecretHash, RedirectURIs, AllowedGrants, AllowedScopes, Status, timestamps

**Invariants:**
- Client must belong to an active tenant
- Name must be 1-128 characters
- OAuthClientID cannot be empty
- RedirectURIs cannot be empty and must be HTTPS or localhost
- AllowedGrants cannot be empty and must be valid grant types
- AllowedScopes cannot be empty
- Confidential clients required for `client_credentials` grant
- Public clients cannot use `client_credentials` grant
- Cannot deactivate already-inactive client
- Cannot reactivate already-active client
- Secret rotation only for confidential clients

**Intent-revealing methods:**
- `IsActive()` - status is active
- `IsConfidential()` - has client secret
- `CanUseGrant(grant)` - grant type allowed
- `Deactivate(now)` - transition to inactive
- `Reactivate(now)` - transition to active

---

## Multi-Tenancy Enforcement

### Service Layer (Defensive)

Service methods have two variants:
- **Scoped:** `GetClientForTenant(ctx, tenantID, clientID)` - enforces tenant boundary
- **Unscoped:** `GetClient(ctx, clientID)` - platform admin only

### Persistence Layer (Structural)

- `ClientStore.FindByTenantAndID()` enforces boundary at data access
- Returns `ErrNotFound` if client exists but belongs to different tenant

### OAuth Resolution (Critical Choke Point)

`ClientService.ResolveClient(ctx, oauthClientID)`:
1. Maps oauthClientID -> Client
2. Checks `client.IsActive()`
3. Loads tenant from `client.TenantID`
4. Checks `tenant.IsActive()`
5. Returns (Client, Tenant) tuple

If tenant or client is inactive, OAuth flows are blocked.

---

## Architecture

### Services

**TenantService** - Tenant lifecycle orchestration
```go
CreateTenant(ctx, name)         // Creates new tenant, validates uniqueness
GetTenant(ctx, tenantID)        // Loads tenant details + counts
DeactivateTenant(ctx, tenantID) // Transitions to inactive, emits audit
ReactivateTenant(ctx, tenantID) // Transitions to active, emits audit
```

**ClientService** - Client registration and lifecycle
```go
CreateClient(ctx, cmd)                     // Registers client, returns secret once
GetClient(ctx, clientID)                   // Platform admin scope
GetClientForTenant(ctx, tenantID, clientID) // Tenant scoped
UpdateClient(ctx, clientID, cmd)           // Updates mutable fields
RotateClientSecret(ctx, clientID)          // Generates new secret (confidential only)
ResolveClient(ctx, oauthClientID)          // OAuth choke point
```

### Ports (Interfaces)

```go
type TenantStore interface {
    CreateIfNameAvailable(ctx, *Tenant) error
    Update(ctx, *Tenant) error
    FindByID(ctx, tenantID) (*Tenant, error)
    FindByName(ctx, name) (*Tenant, error)
    Count(ctx) (int, error)
}

type ClientStore interface {
    Create(ctx, *Client) error
    Update(ctx, *Client) error
    FindByID(ctx, clientID) (*Client, error)
    FindByTenantAndID(ctx, tenantID, clientID) (*Client, error)
    FindByOAuthClientID(ctx, oauthClientID) (*Client, error)
    CountByTenant(ctx, tenantID) (int, error)
}

type UserCounter interface {
    CountByTenant(ctx, tenantID) (int, error)
}

type AuditPublisher interface {
    Emit(ctx, audit.Event) error
}
```

### Adapters

**In-Memory Stores:**
- Thread-safe with RWMutex
- Primary index: `map[ID]*Entity`
- Secondary indexes for lookups:
  - TenantStore: name -> TenantID (case-insensitive)
  - ClientStore: OAuthClientID -> Client
  - ClientStore: TenantID -> client count

**Secrets Adapter** (`secrets/secrets.go`):
- `Generate()` - 32-byte random secret (base64-encoded)
- `Hash(secret)` - bcrypt hash
- `Verify(secret, hash)` - bcrypt comparison

---

## Module Structure

```
internal/tenant/
├── handler/           # HTTP handlers for admin endpoints
├── models/            # Domain entities, value objects, and events
├── readmodels/        # Query-optimized read models (e.g., TenantDetails)
├── secrets/           # Secret generation and hashing
├── service/           # Application services (tenant + client)
└── store/             # Persistence adapters
    ├── tenant/        # Tenant store (PostgreSQL)
    └── client/        # Client store (PostgreSQL)
```

---

## Key Patterns

### Request Validation

Commands follow the Normalize/Validate pattern:

```go
type CreateClientCommand struct { ... }

func (c *CreateClientCommand) Normalize() { ... }
func (c *CreateClientCommand) Validate() error { ... }
```

Validation order: size -> required -> syntax -> semantic.

---

## Audit Events

Events emitted at lifecycle transitions:
- `tenant_created`, `tenant_deactivated`, `tenant_reactivated`
- `client_created`, `client_deactivated`, `client_reactivated`
- `client_secret_rotated` (and `client.secret_rotated` when rotation happens via UpdateClient)

---

## Error Handling

- Stores return sentinel errors (`ErrNotFound`)
- Services translate to domain errors at boundary
- Internal errors never exposed to clients

---

## Product Notes

- Tenant isolation is enforced in service/store methods rather than handlers.
- Auth relies on `ResolveClient` as the canonical client -> tenant lookup.
- Public clients have no secret and cannot use `client_credentials`.

---

## Observability

- Metric: `credo_tenants_created_total` for tenant creation volume.
- Metric: `credo_resolve_client_duration_seconds` histogram for OAuth critical path latency.

---

## Integration Points

- Auth service uses `ResolveClient` for OAuth flows.
- HTTP endpoints (admin-only):
  - `POST /admin/tenants`
  - `GET /admin/tenants/{id}`
  - `POST /admin/tenants/{id}/deactivate`
  - `POST /admin/tenants/{id}/reactivate`
  - `POST /admin/clients`
  - `GET /admin/clients/{id}`
  - `PUT /admin/clients/{id}`
  - `POST /admin/clients/{id}/deactivate`
  - `POST /admin/clients/{id}/reactivate`
  - `POST /admin/clients/{id}/rotate-secret`

---

## Security Considerations

### Cascade Invariant

When a tenant is deactivated, all OAuth flows for its clients fail immediately:

- `ResolveClient()` checks `tenant.IsActive()` as well as `client.IsActive()`
- Clients do NOT need explicit deactivation when tenant is inactive
- This provides single point of enforcement at the OAuth choke point
- Existing tokens remain valid until expiry (revoke separately if needed)

See `models/tenant.go` for the full invariant documentation.

### Client Secret Verification

The service provides constant-time secret verification methods:

```go
// Verify by internal ClientID
VerifyClientSecret(ctx, clientID, providedSecret) error

// Verify by OAuth client_id (public identifier)
VerifyClientSecretByOAuthID(ctx, oauthClientID, providedSecret) error
```

Security properties:
- Uses bcrypt for timing-attack resistant comparison
- Returns same error (`CodeInvalidClient`) for both "not found" and "wrong secret"
- Rejects secret auth for public clients (no secret stored)
- Logs internal details, returns generic message to client

### Secret Handling

- Client secrets are one-time visible (returned only at creation/rotation)
- Secrets are bcrypt-hashed before storage
- `ClientSecretHash` is never serialized (json:"-" tag)
- Secret rotation generates new 32-byte random value

---

## Known Gaps / Follow-ups

- Tenant-admin auth is not yet wired; handlers use platform-admin access paths.
- Persistence uses PostgreSQL stores.
- Consider argon2id for new installations; bcrypt is CPU-bound.
- Grace period for rotated secrets not yet implemented (in-flight requests fail immediately).

---

## Testing

```bash
# Run unit tests
go test ./internal/tenant/...
```

---

## References

- PRD: `docs/prd/PRD-026A-Tenant-Client-Management.md`
- PRD: `docs/prd/PRD-026B-Tenant-Client-Lifecycle.md`
- Architecture: `docs/engineering/architecture.md`
