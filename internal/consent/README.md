# Consent Module

**Purpose:** Manages purpose-based consent following GDPR Article 7 requirements.

---

## Architecture

This module follows **hexagonal architecture** (ports-and-adapters):

```
┌────────────────────────────────────────────────────┐
│                   Transport                        │
│  HTTP handlers (internal/consent/handler)          │
│  - POST /auth/consent                              │
│  - POST /auth/consent/revoke                       │
│  - GET /auth/consent                               │
│  - DELETE /auth/consent                            │
│  - POST /admin/consent/users/{user_id}/revoke-all  │
└──────────────────────────┬─────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────┐
│                Domain (Service + Models)           │
│  consent.Service                                   │
│  - Grant(ctx, userID, purposes)                    │
│  - Revoke(ctx, userID, purposes)                   │
│  - RevokeAll(ctx, userID)                          │
│  - DeleteAll(ctx, userID)                          │
│  - Require(ctx, userID, purpose)                   │
│  - List(ctx, userID, filter)                       │
└──────────────────────────┬─────────────────────────┘
                           │
            ┌──────────────┴──────────────┐
            ▼                             ▼
┌──────────────────────────┐   ┌──────────────────────┐
│ Store (ports.Store)      │   │ Audit Publisher       │
│ - in-memory adapter      │   │ - audit events        │
└──────────────────────────┘   └──────────────────────┘
```

Other modules integrate via **in-process adapters** (e.g., `internal/registry/adapters/consent_adapter.go`).

---

## Domain Design

### Bounded Context

**Context:** `internal/consent`

**Purpose:** Manage purpose-based consent lifecycle:
- Users grant consent for specific purposes (login, registry_check, vc_issuance, decision_evaluation)
- Users revoke consent for specific purposes
- Services check consent before processing sensitive operations
- Audit trail tracks all consent decisions

This is a distinct bounded context because consent management has its own language and invariants separate from authentication, identity, or data processing.

### Ubiquitous Language

| Domain Term        | Code Location                                                              |
| ------------------ | -------------------------------------------------------------------------- |
| **Purpose**        | `models.Purpose` (login, registry_check, vc_issuance, decision_evaluation) |
| **Consent Record** | `models.Record` (persisted consent decision)                               |
| **Status**         | `models.Status` (active, expired, revoked)                                 |
| **Grant**          | `service.Grant()` - create or renew consent                                |
| **Revoke**         | `service.Revoke()` - withdraw consent                                      |
| **Require**        | `service.Require()` - verify consent exists and is active                  |
| **Audit Event**    | emitted via audit publisher at lifecycle transitions                       |

### Aggregate Root and Invariants

**Aggregate Root:** `Record`
- One record per (UserID, Purpose) pair (upsert semantics)
- ID is a UUID (`id.ConsentID`), reused across grant/revoke cycles

**Domain Invariants** (must always hold for stored state):
1. A `Record` must have non-empty `ID`, `UserID`, `Purpose`, `GrantedAt`
2. `Purpose` must be a valid enum value
3. An active record must NOT have `RevokedAt` set
4. An active record must have `ExpiresAt` in the future (or nil for no expiry)
5. A revoked record must have `RevokedAt` set
6. `Status` is computed from `RevokedAt` and `ExpiresAt` at read time

**Policy / API-input Rules** (can change without corrupting stored data):
- Consent TTL duration (default: 1 year; configurable)
- Grant idempotency window (default: 5 minutes; configurable)
- Allowed purposes list

### Transactional Boundaries

Per `AGENTS.md`: "All multi-write operations must be atomic."

The consent service uses `ConsentStoreTx.RunInTx` to wrap multi-purpose operations:
- `service.Grant()` - multiple purposes in a single request
- `service.Revoke()` - multiple purposes in a single request

This prevents partial state if one purpose fails mid-operation.

### Domain Events / Audit

Audit emissions behave like domain events (emitted on lifecycle transitions):

| Transition           | Audit Action           | Decision  |
| -------------------- | ---------------------- | --------- |
| Consent granted      | `consent_granted`      | `granted` |
| Consent revoked      | `consent_revoked`      | `revoked` |
| Consent deleted      | `consent_deleted`      | `revoked` |
| Consent check passed | `consent_check_passed` | `granted` |
| Consent check failed | `consent_check_failed` | `denied`  |

All events include: `user_id`, `purpose`, `reason`, `timestamp`.

---

## Layers

### 1. Domain Layer (Core Business Logic)

**Location:** `service/`, `models/`

**Responsibilities:**
- Enforce consent lifecycle (grant, revoke, expire)
- Validate purposes
- Apply idempotency rules (5-minute window)
- Emit audit events

**No dependencies on:** HTTP/JSON, database implementation

### 2. Ports (Interfaces)

**Location:** `service/service.go`

**Interfaces:**
- `Store` - consent persistence
- `audit.Publisher` - audit event emission

### 3. Adapters (Infrastructure)

**HTTP Adapter (Inbound - from clients)**
- `internal/consent/handler`
- Translates HTTP/JSON -> domain calls
- Maps domain errors -> HTTP status codes
- Extracts user from JWT context

**In-process Adapters (Inbound - from other modules)**
- `internal/registry/adapters/consent_adapter.go`
- Modules such as registry/decision call `ConsentPort` which delegates to the consent service

**Storage Adapter**
- `internal/consent/store/store_memory.go`
- In-memory persistence for demo/dev

---

## Key Concepts

### Purpose-Based Consent

Consent is granted per-purpose, not globally:

```go
const (
    PurposeLogin          = "login"
    PurposeRegistryCheck  = "registry_check"
    PurposeVCIssuance     = "vc_issuance"
    PurposeDecision       = "decision_evaluation"
)
```

### Consent Lifecycle

```
[No Consent] --Grant--> [Active] --Expire--> [Expired]
                          |
                          +-------Revoke----> [Revoked]
```

### Idempotency

Repeated grant requests within the idempotency window return existing consent without:
- Updating timestamps
- Emitting audit events

This prevents audit noise from double-clicks/retries.

### Consent ID Reuse

One consent ID per user+purpose combination:
- Active consent: reuse ID, extend TTL
- Expired consent: reuse ID, renew
- Revoked consent: reuse ID, clear `RevokedAt`

---

## Store Error Contract

The `Store` interface defines error behavior:

```go
// Store defines the persistence interface for consent records.
// Error Contract:
// - FindByUserAndPurpose returns store.ErrNotFound when no record exists
// - Other methods return nil on success or wrapped errors on failure
```

The service maps store errors to domain errors:
- `store.ErrNotFound` -> handled as "missing consent"
- Other errors -> `CodeInternal`

---

## Product Notes

- Consent is purpose-based and time-bound (1 year by default).
- Grant is idempotent within a 5-minute window to reduce audit noise.
- ID reuse keeps one record per user+purpose while audit logs preserve history.

---

## HTTP Endpoints

- `POST /auth/consent` - Grant consent for purposes
- `POST /auth/consent/revoke` - Revoke one or more purposes
- `POST /auth/consent/revoke-all` - Revoke all consents (bulk)
- `GET /auth/consent` - List user's consents
- `DELETE /auth/consent` - Delete all consents (GDPR)
- `POST /admin/consent/users/{user_id}/revoke-all` - Admin revoke-all

---

## Security Considerations

### ConsentID Scoping Invariant

A ConsentID is ALWAYS scoped by (UserID, Purpose). Security implications:

- ConsentID alone is NOT sufficient to authorize access to a record
- All queries MUST include UserID to prevent cross-user access
- Never expose ConsentID in URLs/APIs without validating UserID ownership
- This prevents IDOR vulnerabilities and enumeration attacks

See `models/models.go` for the full invariant documentation.

### Admin Actor Attribution

Admin operations (RevokeAll, DeleteAll) include actor attribution in audit events:

```go
// Admin actor is extracted from X-Admin-Actor-ID header
actorID := admin.GetAdminActorID(ctx)
s.emitAudit(ctx, audit.Event{
    UserID:  targetUserID,
    ActorID: actorID,  // Who performed the action
    Action:  models.AuditActionConsentRevoked,
    ...
})
```

This ensures complete audit trails for compliance and incident investigation.

### Re-Grant Cooldown

The service enforces a cooldown period (default: 5 minutes) after revocation before re-granting:

```go
// models/models.go
func (c Record) CanReGrant(now time.Time, cooldown time.Duration) bool
```

This prevents abuse patterns:
- Rapid revoke→grant cycles to circumvent audit trail analysis
- Race condition exploitation in consent-dependent workflows
- Artificial consent churn for gaming metrics

Configure via `WithReGrantCooldown(duration)` option or `CONSENT_REGRANT_COOLDOWN` environment variable (e.g., `CONSENT_REGRANT_COOLDOWN=5m`).

---

## Known Gaps / Follow-ups

- CQRS projection path deferred until Postgres migration.
- Per-purpose expiry configuration not yet supported.
- Consent cascading/dependencies not yet supported.

---

## Testing

| Layer                   | Location                                   | Purpose                              |
| ----------------------- | ------------------------------------------ | ------------------------------------ |
| Primary (Gherkin)       | `e2e/features/consent_flow.feature`        | Published behavior contracts         |
| Secondary (Integration) | `internal/consent/integration_test.go`     | Timing-sensitive, state manipulation |
| Tertiary (Unit)         | `internal/consent/service/service_test.go` | Error propagation, validation        |

Unit tests exist only to:
- Enforce invariants unreachable via integration tests
- Test error code mapping across boundaries
- Verify store error propagation

---

## Future Enhancements

- **V2:**
  - Per-purpose TTL configuration
  - Consent templates (bundles)
  - Consent delegation (parent -> child)
  - Async background worker for expiry notifications

- **Microservices Migration:**
  - Extract consent service to separate process
  - Add gRPC server adapter
  - No changes to domain logic

---

## Database Migration Strategy

When migrating from in-memory store to PostgreSQL, apply these index strategies:

### Required Indexes

```sql
-- Primary lookup pattern: Require()/FindByUserAndPurpose
CREATE UNIQUE INDEX idx_consents_user_purpose
    ON consents (user_id, purpose)
    WHERE revoked_at IS NULL;

-- List consents for a user (with optional status filter)
CREATE INDEX idx_consents_user_id ON consents (user_id);

-- Admin: find all consents by purpose (analytics, bulk operations)
CREATE INDEX idx_consents_purpose ON consents (purpose);
```

### Query Patterns

| Operation | Query Pattern | Index Used |
|-----------|---------------|------------|
| `Require()` | `WHERE user_id = $1 AND purpose = $2` | `idx_consents_user_purpose` |
| `FindByUserAndPurpose()` | `WHERE user_id = $1 AND purpose = $2` | `idx_consents_user_purpose` |
| `ListByUser()` | `WHERE user_id = $1` | `idx_consents_user_id` |
| `RevokeAllByUser()` | `WHERE user_id = $1 AND revoked_at IS NULL` | `idx_consents_user_purpose` |

### Performance Considerations

1. **Partial Index**: The unique index on `(user_id, purpose)` with `WHERE revoked_at IS NULL` ensures only one active consent per user+purpose while allowing historical revoked records.

2. **Cardinality**: With 4 purposes and N users, expect ~4N records max. Most queries filter by user_id first.

3. **Hot Path**: `Require()` is the hot path (called by registry/decision services). The unique index ensures O(1) lookup.

4. **Expiry Checks**: `expires_at` comparisons happen in application code after fetch. No index needed on `expires_at` for current access patterns.

---

## References

- PRD: `docs/prd/PRD-002-Consent-Management.md`
- API Contract: `api/proto/consent.proto`
- Architecture: `docs/engineering/architecture.md#consent`
