# Consent Module

**Purpose:** Manages purpose-based consent following GDPR Article 7 requirements.

---

## Architecture

This module follows **hexagonal architecture** (ports-and-adapters) pattern:

```
┌─────────────────────────────────────────────────────────┐
│                    External Layer                        │
│  ┌───────────────────────────────────────────────────┐  │
│  │  HTTP Handler (transport/http/handlers_consent.go)│  │
│  │  - POST /auth/consent                             │  │
│  │  - POST /auth/consent/revoke                      │  │
│  │  - GET /auth/consent                              │  │
│  └────────────────────┬──────────────────────────────┘  │
└───────────────────────┼─────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│                  Domain Layer (Core)                     │
│  ┌───────────────────────────────────────────────────┐  │
│  │  consent.Service                                  │  │
│  │  - Grant(ctx, userID, purposes)                   │  │
│  │  - Revoke(ctx, userID, purposes)                  │  │
│  │  - Require(ctx, userID, purpose) -> error         │  │
│  │  - List(ctx, userID, filter)                      │  │
│  └───────────────┬───────────────────────────────────┘  │
│                  │                                       │
│                  │ Depends on                            │
│                  ▼                                       │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Ports (Interfaces)                               │  │
│  │  - Store interface                                │  │
│  │  - audit.Publisher interface                      │  │
│  └───────────────────────────────────────────────────┘  │
└──────────────────────┬──────────────────────────────────┘
                       │
                       │ Implemented by
                       ▼
┌─────────────────────────────────────────────────────────┐
│               Infrastructure Layer                       │
│  ┌──────────────────┐    ┌──────────────────────────┐   │
│  │ Adapters         │    │  Storage                 │   │
│  │  - gRPC Server   │    │  - InMemoryStore         │   │
│  │    (inbound)     │    │  - PostgresStore (V2)    │   │
│  └──────────────────┘    └──────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

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
| **Audit Event**    | emitted via `audit.Publisher` at lifecycle transitions                     |

### Aggregate Root and Invariants

**Aggregate Root:** `Record`
- One record per (UserID, Purpose) pair (upsert semantics)
- ID format: `consent_{uuid}`

**Domain Invariants** (must always hold for stored state):
1. A `Record` must have non-empty `ID`, `UserID`, `Purpose`, `GrantedAt`
2. `Purpose` must be a valid enum value (login, registry_check, vc_issuance, decision_evaluation)
3. An active record must NOT have `RevokedAt` set
4. An active record must have `ExpiresAt` in the future (or nil for no expiry)
5. A revoked record must have `RevokedAt` set
6. `Status` is computed from `RevokedAt` and `ExpiresAt` at read time

**Policy / API-input Rules** (can change without corrupting stored data):
- Consent TTL duration (default: 1 year)
- Grant idempotency window (default: 5 minutes)
- Allowed purposes list

### Transactional Boundaries

Per `AGENTS.md`: "All multi-write operations must be atomic."

The consent service uses `ConsentStoreTx.RunInTx` to wrap multi-purpose operations:
- `service.Grant()` - multiple purposes in single request
- `service.Revoke()` - multiple purposes in single request

This prevents partial state if one purpose fails mid-operation.

### Domain Events / Audit

Audit emissions behave like domain events (emitted on lifecycle transitions):

| Transition           | Audit Action           | Decision  |
| -------------------- | ---------------------- | --------- |
| Consent granted      | `consent_granted`      | `granted` |
| Consent revoked      | `consent_revoked`      | `revoked` |
| Consent check passed | `consent_check_passed` | `granted` |
| Consent check failed | `consent_check_failed` | `denied`  |

All events include: `user_id`, `purpose`, `reason`, `timestamp`

---

## Layers

### 1. Domain Layer (Core Business Logic)

**Location:** `service/`, `models/`

**Responsibilities:**
- Enforce consent lifecycle (grant, revoke, expire)
- Validate purposes
- Apply idempotency rules (5-minute window)
- Emit audit events

**No dependencies on:** gRPC/Protobuf, HTTP/JSON, Database implementation

### 2. Ports (Interfaces)

**Location:** `service/service.go`

**Interfaces:**
- `Store` - Consent persistence
- `audit.Publisher` - Audit event emission

### 3. Adapters (Infrastructure)

#### HTTP Adapter (Outbound - to clients)
**Location:** `internal/transport/http/handlers_consent.go`
- Translates HTTP/JSON → Domain calls
- Maps domain errors → HTTP status codes
- Extracts user from JWT context

#### gRPC Server Adapter (Inbound - from other services)
**Location:** `adapters/grpc/server.go`
- Exposes consent service over gRPC
- Implements `consentpb.ConsentServiceServer`
- Translates Protobuf <-> Domain models
- Used by: registry, decision, vc services

#### Storage Adapter
**Location:** `store/store_memory.go`
- Implements `Store` interface
- Handles persistence details

---

## Interservice Communication

### Consumed by (Inbound gRPC Calls)

Other services call consent service via gRPC:

1. **Registry Service** - Check consent before citizen/sanctions lookup
2. **VC Service** - Check consent before issuing credentials
3. **Decision Service** - Check consent before evaluation
4. **Biometric Service** - Check consent before face matching

### Provides (gRPC API)

**Service:** `ConsentService` (defined in `api/proto/consent.proto`)

**Methods:**
- `HasConsent(userID, purpose) -> bool`
- `RequireConsent(userID, purpose) -> error`
- `GrantConsent(userID, purposes[]) -> ConsentRecord[]`
- `RevokeConsent(userID, purposes[]) -> ConsentRecord[]`
- `ListConsents(userID) -> ConsentRecord[]`

---

## Key Concepts

### Purpose-Based Consent

Consent is granted per-purpose, not globally:

```go
const (
    PurposeLogin                = "login"
    PurposeRegistryCheck        = "registry_check"
    PurposeVCIssuance           = "vc_issuance"
    PurposeDecisionEvaluation   = "decision_evaluation"
    PurposeBiometricVerification = "biometric_verification"
)
```

### Consent Lifecycle

```
[No Consent] --Grant--> [Active] --Expire--> [Expired]
                          |
                          +-------Revoke----> [Revoked]
```

### Idempotency

Repeated grant requests within 5 minutes return existing consent without:
- Updating timestamps
- Emitting audit events

This prevents audit noise from double-clicks/retries.

### Consent ID Reuse

One consent ID per user+purpose combination:
- Active consent: reuse ID, extend TTL
- Expired consent: reuse ID, renew
- Revoked consent: reuse ID, clear RevokedAt

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
  - Run gRPC server on port 9091
  - Other services connect via `consent-service:9091`
  - No code changes to domain logic

---

## References

- PRD: [PRD-002-Consent-Management.md](../../docs/prd/PRD-002-Consent-Management.md)
- API Contract: [api/proto/consent.proto](../../api/proto/consent.proto)
- Architecture: [docs/architecture.md](../../docs/architecture.md#consent)
