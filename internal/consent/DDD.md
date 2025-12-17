# DDD in the Consent Module

This document describes the Domain-Driven Design (DDD) approach applied to the `internal/consent` bounded context in Credo.

---

## 1) Bounded Context Definition

**Context:** `internal/consent`

**Purpose:** Manage purpose-based consent lifecycle:

- Users grant consent for specific purposes (login, registry_check, vc_issuance, decision_evaluation)
- Users revoke consent for specific purposes
- Services check consent before processing sensitive operations
- Audit trail tracks all consent decisions

This is a distinct bounded context because consent management has its own language and invariants separate from authentication, identity, or data processing.

---

## 2) Ubiquitous Language Mapping (code <-> terms)

| Domain Term        | Code Location                                                              |
| ------------------ | -------------------------------------------------------------------------- |
| **Purpose**        | `models.Purpose` (login, registry_check, vc_issuance, decision_evaluation) |
| **Consent Record** | `models.Record` (persisted consent decision)                               |
| **Status**         | `models.Status` (active, expired, revoked)                                 |
| **Grant**          | `service.Grant()` - create or renew consent                                |
| **Revoke**         | `service.Revoke()` - withdraw consent                                      |
| **Require**        | `service.Require()` - verify consent exists and is active                  |
| **Audit Event**    | emitted via `audit.Publisher` at lifecycle transitions                     |

---

## 3) Layering / Module Roles

This aligns with Credo's `AGENTS.md` rules:

- **Handlers** (`internal/consent/handler/*`)

  - HTTP concerns only: decode, validate request, extract context, map responses.

- **Application Service** (`internal/consent/service/*`)

  - Orchestration + domain behavior + error mapping.
  - Transaction boundaries via `ConsentStoreTx.RunInTx`.

- **Domain Models** (`internal/consent/models/*`)

  - Entities representing persisted consent state (`Record`).
  - Value objects (`Purpose`, `Status`).
  - Request/Response DTOs (`GrantRequest`, `RevokeRequest`, etc.).

- **Stores / Repositories** (`internal/consent/store/*`)
  - Persistence adapters behind interfaces (`Store`).
  - Currently: in-memory implementation.

---

## 4) Aggregate Root and Invariants

### Aggregate Root

- **Record** is the aggregate root for consent state
- One record per (UserID, Purpose) pair (upsert semantics)
- ID format: `consent_{uuid}`

### Domain Invariants (must always hold for stored state)

1. A `Record` must have non-empty `ID`, `UserID`, `Purpose`, `GrantedAt`
2. `Purpose` must be a valid enum value (login, registry_check, vc_issuance, decision_evaluation)
3. An active record must NOT have `RevokedAt` set
4. An active record must have `ExpiresAt` in the future (or nil for no expiry)
5. A revoked record must have `RevokedAt` set
6. `Status` is computed from `RevokedAt` and `ExpiresAt` at read time

### Policy / API-input Rules (can change without corrupting stored data)

- Consent TTL duration (default: 1 year)
- Grant idempotency window (default: 5 minutes)
- Allowed purposes list

---

## 5) Transactional Boundaries

Per `AGENTS.md`: "All multi-write operations must be atomic."

The consent service uses `ConsentStoreTx.RunInTx` to wrap multi-purpose operations:

- `service.Grant()` - multiple purposes in single request
- `service.Revoke()` - multiple purposes in single request

This prevents partial state if one purpose fails mid-operation.

Implementation:

- `internal/consent/service/tx.go` - interface definition
- `internal/consent/service/service.go` - mutex-based implementation for in-memory store

---

## 6) Domain Events / Audit

Audit emissions behave like domain events (sentinel emitted on lifecycle transitions):

| Transition           | Audit Action           | Decision  |
| -------------------- | ---------------------- | --------- |
| Consent granted      | `consent_granted`      | `granted` |
| Consent revoked      | `consent_revoked`      | `revoked` |
| Consent check passed | `consent_check_passed` | `granted` |
| Consent check failed | `consent_check_failed` | `denied`  |

All events include:

- `user_id`
- `purpose`
- `reason` (currently: `user_initiated`)
- `timestamp`

---

## 7) Store Error Contract

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

## 8) Testing Doctrine Alignment

Per `testing.md` and `AGENTS.md`:

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

## 9) Current Deviations / Future Improvements

1. **Models mix domain and transport concerns**

   - `models/models.go` contains both `Record` (domain) and `GrantRequest` (transport)
   - Could split into `models/domain.go` and `models/transport.go`

2. **Invariants not enforced via constructors**

   - Entities created via struct literals
   - Could add `NewRecord()` constructor to enforce invariants

3. **Status computed at read time**
   - `ComputeStatus()` recalculates on every read
   - Acceptable for MVP but could be optimized with status update on write
