# PRD-002: Consent Management System

**Status:** Implementation Required (TR-6 projections deferred; see [PRD-002B](./PRD-002B-Consent-Projections-Read-Model.md))
**Priority:** P0 (Critical)
**Owner:** Engineering Team
**Last Updated:** 2025-12-17

---

## 1. Overview

### Problem Statement

In regulated domains (GDPR, HIPAA, financial services), consent is not a simple checkbox. It must be:

- **Purpose-specific** - Users consent to specific uses of their data
- **Time-bound** - Consent has expiry dates and can be revoked
- **Auditable** - System must prove consent existed at the time of data processing
- **Granular** - Users can consent to some purposes while denying others

Credo requires a robust consent management system that enforces these requirements at the API level.

### Goals

- Implement purpose-based consent model
- Support consent granting, revocation, and expiry
- Enforce consent checks before sensitive operations
- Maintain audit trail of all consent changes
- Provide user visibility into granted consents

### Non-Goals

- Consent UI/frontend (API-only)
- Consent renewal workflows (manual re-grant for MVP)
- Consent withdrawal period (immediate revocation)
- Consent cascading (if A requires B, B must be granted first)
- Conditional consent (consent with additional terms)

---

## 2. User Stories

**As a** user
**I want to** grant consent for specific purposes
**So that** the system can process my data lawfully

**As a** user
**I want to** revoke consent at any time
**So that** I maintain control over my data

**As a** developer
**I want to** check if a user has consented to a purpose
**So that** I can enforce data processing rules

**As a** compliance officer
**I want to** audit all consent grants and revocations
**So that** I can prove regulatory compliance

---

## 2.1 Use Case Taxonomy, Permissions, and Audit Attribution

This PRD defines **user self-service** consent management. Admin workflows are
defined in PRD-002C and are referenced here to clarify permissions and audit
taxonomy.

| Use case | Actor | Endpoint(s) | Permission boundary | Audit reason | Actor ID |
| --- | --- | --- | --- | --- | --- |
| Normal grant/revoke | User | `POST /auth/consent`, `POST /auth/consent/revoke` | User can only act on own consents | `user_initiated` | Not required |
| Bulk pause (revoke-all) | User | `POST /auth/consent/revoke-all` | User can only act on own consents | `user_bulk_revocation` | Not required |
| GDPR self-service delete | User | `DELETE /auth/consent` | User can only delete own consents | `gdpr_self_service` | Not required |
| Security revoke (admin) | Admin | `POST /admin/consent/users/{user_id}/revoke`, `POST /admin/consent/users/{user_id}/revoke-all` | Admin can revoke any user | `security_concern` | Required |
| GDPR delete (admin) | Admin | `DELETE /admin/consent/users/{user_id}` | Admin can delete any user | `gdpr_erasure_request` (+ reference) | Required |

Audit reasons are intentional and distinct so that user actions, security
responses, and GDPR/legal requests are independently traceable.

---

## 3. Functional Requirements

### FR-1: Grant Consent

**Endpoint:** `POST /auth/consent`

**Description:** Grant consent for one or more purposes. If consent already exists for a purpose, it's renewed with a new expiry date.

**Input:**

```json
{
  "purposes": ["login", "registry_check", "vc_issuance"]
}
```

**Output (Success - 200):**

```json
{
  "granted": [
    {
      "purpose": "login",
      "granted_at": "2025-12-03T10:00:00Z",
      "expires_at": "2026-12-03T10:00:00Z",
      "status": "active"
    },
    {
      "purpose": "registry_check",
      "granted_at": "2025-12-03T10:00:00Z",
      "expires_at": "2026-12-03T10:00:00Z",
      "status": "active"
    },
    {
      "purpose": "vc_issuance",
      "granted_at": "2025-12-03T10:00:00Z",
      "expires_at": "2026-12-03T10:00:00Z",
      "status": "active"
    }
  ],
  "message": "Consent granted for 3 purposes"
}
```

**Authentication:**

- Requires valid JWT bearer token in Authorization header
- JWT must contain valid user_id, session_id, and client_id claims
- Token validated via RequireAuth middleware

**Business Logic:**

1. Extract user_id from JWT claims (populated by RequireAuth middleware in context)
2. Validate all purposes are in allowed enum
3. For each purpose:
   - Check if consent already exists for this user+purpose
   - If exists and active:
     - **Idempotency Window**: If granted < 5 minutes ago, return existing without update (no audit event)
     - If granted ≥ 5 minutes ago, update expiry date (renewal) and emit audit event
   - If exists and expired/revoked: Reuse existing consent ID, update timestamps, clear RevokedAt, emit audit event
   - If not exists, create new consent record with new ID
4. For each consent:
   - Reuse existing ID or generate unique consent ID (format: `consent_<uuid>`)
   - Set GrantedAt = current timestamp (if updating)
   - Set ExpiresAt = current timestamp + 1 year (if updating)
   - Set RevokedAt = nil (if updating)
   - Save to ConsentStore (Update for existing, Save for new)
5. Emit audit event for each granted purpose (skipped if within idempotency window)
6. Return list of granted consents

**Idempotency Behavior:**

To prevent audit noise from rapid repeated requests (double-clicks, retries), consent grants are idempotent within a **5-minute window**:

- If user re-requests consent for an **active** purpose that was granted < 5 minutes ago → Return existing consent without update, no audit event
- If user re-requests consent for an **active** purpose that was granted ≥ 5 minutes ago → Update timestamps and extend TTL, emit audit event (supports long-running sessions)
- If user re-requests consent for an **expired** or **revoked** purpose → Always update regardless of time window

This approach:

- ✅ Prevents duplicate audit events from accidental double-clicks
- ✅ Supports legitimate TTL extensions for active sessions
- ✅ Ensures expired/revoked consents are always renewable immediately

**Consent ID Reuse:**

The system always reuses existing consent IDs (whether active, expired, or revoked) to maintain a clean database. Consent history is tracked through the audit log, not by creating multiple consent records per user+purpose.

**Validation:**

- User must be authenticated (valid bearer token)
- Purposes array must not be empty
- Each purpose must match ConsentPurpose enum

**Error Cases:**

- 401 Unauthorized: Invalid or missing bearer token
- 400 Bad Request: Empty purposes array
- 400 Bad Request: Invalid purpose value
- 500 Internal Server Error: Store failure

**Audit Event:**

```json
{
  "action": "consent_granted",
  "user_id": "user_123",
  "purpose": "registry_check",
  "decision": "granted",
  "reason": "user_initiated"
}
```

---

### FR-2: Revoke Consent

**Endpoint:** `POST /auth/consent/revoke`

**Description:** Revoke consent for one or more purposes. Once revoked, future operations requiring that purpose will fail until consent is re-granted.

**Input:**

```json
{
  "purposes": ["registry_check"]
}
```

**Output (Success - 200):**

```json
{
  "revoked": [
    {
      "purpose": "registry_check",
      "revoked_at": "2025-12-03T11:00:00Z",
      "status": "revoked"
    }
  ],
  "message": "Consent revoked for 1 purpose"
}
```

**Authentication:**

- Requires valid JWT bearer token in Authorization header
- Token validated via RequireAuth middleware

**Permissions:**

- User can only revoke their own consents
- Admin revocations use separate endpoints with distinct audit reasons (see PRD-002C)

**Business Logic:**

1. Extract user_id from JWT claims (populated by RequireAuth middleware in context)
2. Validate all purposes are in allowed enum
3. For each purpose:
   - Find active consent for this user+purpose
   - If not found or already revoked, skip (idempotent)
   - If found and active:
     - Set RevokedAt = current timestamp
     - Update ConsentStore
4. Emit audit event for each revoked purpose
5. Return list of revoked consents

**Error Cases:**

- 401 Unauthorized: Invalid or missing bearer token
- 400 Bad Request: Empty purposes array
- 400 Bad Request: Invalid purpose value
- 500 Internal Server Error: Store failure

**Audit Event:**

```json
{
  "action": "consent_revoked",
  "user_id": "user_123",
  "purpose": "registry_check",
  "decision": "revoked",
  "reason": "user_initiated"
}
```

---

### FR-2.1: Revoke All Consents (Bulk)

**Endpoint:** `POST /auth/consent/revoke-all`

**Description:** Revoke all active consents for the authenticated user. This is a self-service bulk pause. Admin bulk revocation for security response uses `/admin/consent/...` endpoints (PRD-002C). Already revoked or expired consents are not affected.

**Input:**

- Header: `Authorization: Bearer <token>`
- No request body required

**Output (Success - 200):**

```json
{
  "revoked": null,
  "message": "Consent revoked for 3 purposes"
}
```

**Authentication:**

- Requires valid JWT bearer token in Authorization header
- Token validated via RequireAuth middleware

**Business Logic:**

1. Extract user_id from JWT claims (populated by RequireAuth middleware in context)
2. Find all consent records for user
3. For each record where RevokedAt is nil:
   - Set RevokedAt = current timestamp
   - Update ConsentStore
4. Emit single audit event with bulk_revocation reason
5. Return count of revoked consents

**Error Cases:**

- 401 Unauthorized: Invalid or missing bearer token
- 500 Internal Server Error: Store failure

**Audit Event:**

```json
{
  "action": "consent_revoked",
  "user_id": "user_123",
  "decision": "revoked",
  "reason": "user_bulk_revocation"
}
```

**Use Cases:**

- Test isolation: Clear consent state between test scenarios
- Administrative cleanup: Revoke all consents before account deletion
- User-initiated "reset all": Clear all permissions at once

---

### FR-2.2: Delete All Consents (GDPR Right to Erasure)

**Endpoint:** `DELETE /auth/consent`

**Description:** Permanently delete all consent records for the authenticated user. This is a destructive **self-service GDPR** operation (Article 17). Admin-initiated GDPR deletion uses `/admin/consent/...` endpoints with legal reference tracking (PRD-002C). Unlike revoke-all, this removes records entirely rather than marking them as revoked.

**Input:**

- Header: `Authorization: Bearer <token>`
- No request body required

**Output (Success - 200):**

```json
{
  "message": "All consents deleted"
}
```

**Authentication:**

- Requires valid JWT bearer token in Authorization header
- Token validated via RequireAuth middleware

**Business Logic:**

1. Extract user_id from JWT claims (populated by RequireAuth middleware in context)
2. Delete all consent records for user from ConsentStore
3. Emit single audit event with bulk_deletion reason
4. Return success message

**Error Cases:**

- 401 Unauthorized: Invalid or missing bearer token
- 500 Internal Server Error: Store failure

**Audit Event:**

```json
{
  "action": "consent_deleted",
  "user_id": "user_123",
  "decision": "deleted",
  "reason": "gdpr_self_service"
}
```

**Use Cases:**

- GDPR right to erasure (Article 17) requests
- Account deletion workflows
- Test cleanup (provides complete isolation between test scenarios)

**Important Considerations:**

- This operation is **irreversible**. Deleted consents cannot be recovered.
- For audit trail preservation, consider using `POST /auth/consent/revoke-all` unless full erasure is legally required.
- The audit event itself is retained (audit logs are append-only) but the consent records are removed.

---

### FR-3: List User Consents

**Endpoint:** `GET /auth/consent`

**Description:** List all consent records for the authenticated user, including active, expired, and revoked consents.

**Input:**

- Header: `Authorization: Bearer <token>`
- Query Parameters (optional):
  - `status` - Filter by status: "active", "expired", "revoked"
  - `purpose` - Filter by specific purpose

**Output (Success - 200):**

```json
{
  "consents": [
    {
      "id": "consent_abc123",
      "purpose": "login",
      "granted_at": "2025-12-03T10:00:00Z",
      "expires_at": "2026-12-03T10:00:00Z",
      "revoked_at": null,
      "status": "active"
    },
    {
      "id": "consent_def456",
      "purpose": "registry_check",
      "granted_at": "2025-12-03T10:00:00Z",
      "expires_at": "2026-12-03T10:00:00Z",
      "revoked_at": "2025-12-03T11:00:00Z",
      "status": "revoked"
    }
  ]
}
```

**Authentication:**

- Requires valid JWT bearer token in Authorization header
- Token validated via RequireAuth middleware

**Business Logic:**

1. Extract user_id from JWT claims (populated by RequireAuth middleware in context)
2. Retrieve all consents for user from ConsentStore
3. Apply filters if provided (status, purpose)
4. For each consent, calculate status:
   - If RevokedAt != nil: status = "revoked"
   - Else if ExpiresAt < now: status = "expired"
   - Else: status = "active"
5. Return filtered list

**Error Cases:**

- 401 Unauthorized: Invalid or missing bearer token
- 400 Bad Request: Invalid filter value
- 500 Internal Server Error: Store failure

---

### FR-4: Require Consent (Internal API)

**Function:** `consentService.Require(ctx, userID, purpose)`

**Description:** Internal service method used by other handlers to enforce consent before processing data. This is NOT an HTTP endpoint but a service method called programmatically.

**Usage Example:**

```go
// In any handler that processes user data
err := h.consentService.Require(ctx, userID, consent.ConsentPurposeRegistryCheck)
if err != nil {
    writeError(w, err) // Returns 403 with MissingConsent error
    return
}
// Proceed with registry lookup
```

**Business Logic:**

1. Find active consent for user+purpose
2. If not found, return `ErrMissingConsent`
3. Check if expired: ExpiresAt < now
4. If expired, return `ErrConsentExpired`
5. Check if revoked: RevokedAt != nil
6. If revoked, return `ErrConsentRevoked`
7. Return nil (consent is valid)

**Error Returns:**

- `errors.CodeMissingConsent` (403) - No consent granted
- `errors.CodeInvalidConsent` (403) - Consent expired or revoked
- `errors.CodeInternal` (500) - Store failure

---

## 4. Technical Requirements

### TR-1: Data Models

**ConsentPurpose Enum** (Location: `internal/consent/models.go`)

```go
type ConsentPurpose string

const (
    ConsentPurposeLogin         ConsentPurpose = "login"
    ConsentPurposeRegistryCheck ConsentPurpose = "registry_check"
    ConsentPurposeVCIssuance    ConsentPurpose = "vc_issuance"
    ConsentPurposeDecision      ConsentPurpose = "decision_evaluation"
)

func (cp ConsentPurpose) IsValid() bool {
    // Validate against allowed values
}
```

**ConsentRecord Model** (Location: `internal/consent/models.go`)

```go
type ConsentRecord struct {
    ID        string         // Format: "consent_<uuid>"
    UserID    string         // Foreign key to User.ID
    Purpose   ConsentPurpose // Specific purpose
    GrantedAt time.Time      // When consent was granted
    ExpiresAt *time.Time     // When consent expires (nil = never)
    RevokedAt *time.Time     // When consent was revoked (nil = not revoked)
}

func (c *ConsentRecord) IsActive(now time.Time) bool {
    // Returns true if not revoked and not expired
    if c.RevokedAt != nil {
        return false
    }
    if c.ExpiresAt != nil && c.ExpiresAt.Before(now) {
        return false
    }
    return true
}
```

### TR-2: Storage Interface

**ConsentStore** (Location: `internal/consent/store.go`)

```go
type Store interface {
    Save(ctx context.Context, record *ConsentRecord) error
    FindByUserAndPurpose(ctx context.Context, userID string, purpose ConsentPurpose) (*ConsentRecord, error)
    ListByUser(ctx context.Context, userID string) ([]*ConsentRecord, error)
    Update(ctx context.Context, record *ConsentRecord) error
    RevokeByUserAndPurpose(ctx context.Context, userID string, purpose ConsentPurpose, revokedAt time.Time) error
    RevokeAllByUser(ctx context.Context, userID string, revokedAt time.Time) (int, error) // Bulk revoke
    DeleteByUser(ctx context.Context, userID string) error // For GDPR
}
```

**Implementation:** Use `internal/consent/store_memory.go` (already exists)

### TR-3: Service Layer

**ConsentService** (Location: `internal/consent/service.go`)

```go
type Service struct {
    store     Store
    auditor   audit.Publisher
    ttl       time.Duration  // Consent expiry duration (default: 365 days)
}

// Grant accepts multiple purposes and grants/renews consent for each
// Returns idempotently if consent was granted < 5 minutes ago (active only)
func (s *Service) Grant(ctx context.Context, userID string, purposes []Purpose) ([]*Record, error)

// Revoke accepts multiple purposes and revokes consent for each
func (s *Service) Revoke(ctx context.Context, userID string, purposes []Purpose) ([]*Record, error)

// RevokeAll revokes all active consents for a user (bulk operation)
func (s *Service) RevokeAll(ctx context.Context, userID string) (*RevokeResponse, error)

// DeleteAll permanently removes all consent records for a user (GDPR erasure)
func (s *Service) DeleteAll(ctx context.Context, userID string) error

// List returns all consent records for a user (optionally filtered)
func (s *Service) List(ctx context.Context, userID string, filter *RecordFilter) ([]*Record, error)

// Require checks if user has active consent for a purpose (internal validation method)
func (s *Service) Require(ctx context.Context, userID string, purpose Purpose) error
```

**Key Implementation Details:**

- **Idempotency Window**: 5 minutes for active consents (configurable via comment in code)
- **ID Reuse**: Always reuses existing consent IDs (active, expired, revoked)
- **Audit Events**: Emitted on every update except within idempotency window
- **TTL**: 365 days by default (configurable via service constructor)

### TR-4: HTTP Handlers

**Handler Functions** (Location: `internal/transport/http/handlers_consent.go`)

```go
func (h *Handler) handleConsent(w http.ResponseWriter, r *http.Request)
func (h *Handler) handleConsentRevoke(w http.ResponseWriter, r *http.Request)
func (h *Handler) handleConsentList(w http.ResponseWriter, r *http.Request)
```

### TR-5: Error Types

**Consent-Specific Errors** (Location: `pkg/errors/errors.go`)

- `CodeMissingConsent` - User has not granted consent for purpose
- `CodeInvalidConsent` - Consent expired or revoked
- Both map to HTTP 403 Forbidden

### TR-6: CQRS Read Model & Projection Store (Deferred)

**Status:** Deferred until after Postgres migration. Tracked in [PRD-002B](./PRD-002B-Consent-Projections-Read-Model.md).

**Status:** Future Enhancement (Post-MVP)
**Priority:** P2 (Performance Optimization)
**When to Implement:** When read latency > 100ms p95 or write contention causes throughput issues

---

#### Problem & Solution

**Problem:**

- `Require()` is called on **every** registry lookup, VC issuance, decision evaluation
- High read-to-write ratio (100:1+ in production)
- Current implementation reads from same store as writes → contention

**Solution:**

- Separate optimized read model for fast `user_id:purpose` lookups
- Async projection updates don't block write path
- Sub-5ms read latency

---

#### Architecture

```
WRITE PATH (Grant/Revoke):
  Handler → Service → ConsentStore (primary)
                   └→ EventBus → ProjectionWorker → ProjectionStore

READ PATH (Require):
  Service.Require() → ProjectionStore (fast, <5ms)
                   └→ ConsentStore (fallback if cache miss)
```

#### Components

##### 1. Projection Data Structure

**Location:** `internal/consent/projection/models.go`

- `ConsentProjection` struct with fields:
  - `UserID`, `Purpose`, `Status` (active/revoked/expired)
  - `ExpiresAt`, `RevokedAt`, `Version` (for optimistic locking)
- Key format: `consent:{userID}:{purpose}`
- Method: `IsActive()` - fast status check

##### 2. Projection Store Interface

**Location:** `internal/consent/projection/store.go`

```
Interface: projection.Store
├── Get(ctx, userID, purpose) → Projection | ErrNotFound
├── Set(ctx, projection) → ErrVersionConflict if stale
├── Delete(ctx, userID, purpose)
├── DeleteByUser(ctx, userID) → for GDPR
└── BatchSet(ctx, []projections) → atomic updates
```

**Implementations:**

- `store_memory.go` - In-memory map (dev/testing)
- `store_redis.go` - Redis Cluster (production)

##### 3. Event Infrastructure

**Location:** `internal/consent/events/`

- `ConsentChanged` event:
  - Fields: `UserID`, `Purpose`, `Action` (granted/revoked), `Status`, `Version`, `Timestamp`
  - Topic: `"consent.changed"`

**Location:** `internal/platform/eventbus/`

- `EventPublisher` interface:
  - `Publish(ctx, topic, event)`
- Implementations:
  - `memory.go` - In-process channels (MVP)
  - `nats.go` - NATS/Kafka (production)

##### 4. Projection Worker

**Location:** `internal/consent/projection/worker.go`

- `Worker` struct:
  - Subscribes to `"consent.changed"` topic
  - Calls `projectionStore.Set()` with version check
  - Handles `ErrVersionConflict` gracefully (log, ignore)
  - Retries on other errors

##### 5. Service Integration

**Changes to:** `internal/consent/service/service.go`

Add to `Service` struct:

- `projectionStore projection.Store` (optional, nil for MVP)
- `eventPublisher EventPublisher` (optional, nil for MVP)

Update methods:

- `Grant()` / `Revoke()`: Publish `ConsentChanged` event after writing
- `Require()`: Check `projectionStore` first, fallback to `store`

---

#### Directory Structure

```
internal/consent/
├── service/service.go              # Updated with projection hooks
├── projection/
│   ├── models.go                   # ConsentProjection struct
│   ├── store.go                    # Store interface + ErrVersionConflict
│   ├── store_memory.go             # In-memory implementation
│   ├── store_redis.go              # Redis implementation (future)
│   ├── worker.go                   # Event consumer & projection updater
│   └── *_test.go
├── events/
│   ├── events.go                   # ConsentChanged event definition
│   └── publisher.go                # EventPublisher interface

internal/platform/eventbus/
├── memory.go                       # In-memory pub/sub
├── nats.go                         # NATS integration (future)
└── *_test.go

cmd/server/main.go                  # Wire up worker: go worker.Start(ctx)
```

---

#### Implementation Phases

**Phase 1: Foundation** (2-3 hours)

- Create `projection/` package with `Store` interface
- Implement `InMemoryStore` with optimistic locking
- Add tests for version conflicts

**Phase 2: Events** (3-4 hours)

- Create `events/` package with `ConsentChanged`
- Implement in-memory `EventPublisher`
- Update `Service.Grant/Revoke` to publish events
- Integration tests

**Phase 3: Worker** (2-3 hours)

- Implement `projection.Worker`
- Wire up in `main.go` as goroutine
- Add lifecycle tests (start/stop)

**Phase 4: Service Integration** (2 hours)

- Update `Service.Require()` to read from projection first
- Add fallback logic for projection failures
- Performance benchmarks

**Phase 5: Redis (Optional)** (4-6 hours)

- Implement `RedisStore` with WATCH for optimistic locking
- Add configuration for Redis connection
- Deploy & performance testing

**Total Effort:** 11-16 hours

---

#### Key Design Decisions

##### Optimistic Locking

- Use monotonic version (e.g., Unix timestamp nanos)
- Projection worker rejects updates with `version <= existing.version`
- Prevents stale writes when events arrive out-of-order

##### Eventual Consistency

- Projection lag budget: ≤ 1 second
- On stale read, downstream can re-check canonical store
- Monitor lag via metrics: `projection_lag_seconds`

##### Fallback Strategy

```
Require() flow:
1. Try projectionStore.Get() → fast path (<5ms)
2. On ErrNotFound → fallback to store.FindByUserAndPurpose()
3. On other error → log warning, use fallback
4. Always correct because canonical store is source of truth
```

##### In-Memory First, Redis Later

- Start with `InMemoryStore` (simple, testable)
- Same interface as Redis → easy migration
- Switch to Redis when scale requires it

---

#### Testing Strategy

**Unit Tests:**

- Projection store optimistic locking
- Event serialization
- Worker handles version conflicts

**Integration Tests:**

- End-to-end: Grant → Event → Worker → Projection → Require
- Verify projection lag < 100ms
- Test fallback when projection missing

**Load Tests:**

- Measure read latency improvement (projection vs canonical)
- Verify projection handles 1000+ writes/sec

---

#### Operational Considerations

**Metrics:**

```
projection_updates_total{purpose}
projection_read_hits_total
projection_read_misses_total
projection_version_conflicts_total
projection_lag_seconds
```

**Alerts:**

- Projection lag > 5 seconds → P2
- Projection read errors > 1% → P1

**Tools:**

- Replay command: Rebuild projections from audit log
- Verify command: Check consistency between projection and canonical store

---

#### Configuration Example

```yaml
consent:
  projection:
    enabled: false # Enable projections
    type: "memory" # "memory" | "redis"
    ttl: "366h" # Projection expiry
    fallback: true # Fall back to canonical on error

  redis: # Only if type=redis
    addr: "localhost:6379"
    password: ""
    db: 0
```

---

#### When NOT to Implement

- MVP/early stage: Current implementation is sufficient
- Low traffic: < 100 req/sec for `Require()`
- Simple architecture preferred over performance optimization

**Trigger for Implementation:**

- Read latency p95 > 100ms
- Write contention causing throughput bottlenecks
- Need to scale reads independently from writes

#### Acceptance & Testing Expectations for TR-6

- **Acceptance:** When projections are enabled, `Require()` performs primary lookups against the projection store and only falls back to the canonical store on cache miss/error, while preserving the same error codes and audit behavior as the canonical-only path.
- **Integration Tests:**
  - Enable projection store (memory/redis) and assert `Require()` reads from projection path and tolerates projection cache misses by falling back to the canonical store.
  - Grant/Revoke flows publish projection updates and reflect in subsequent `Require()` calls without additional writes to the canonical store.
  - Projection version conflicts are handled (retry or surfaced) without breaking the write path.
- **Load Tests (non-blocking for MVP):** Demonstrate sub-5ms `Require()` latency for projection hits under 100:1 read/write ratios.

---

## 5. API Specifications

### Endpoint Summary

| Endpoint                   | Method | Auth Required | Purpose              |
| -------------------------- | ------ | ------------- | -------------------- |
| `/auth/consent`            | POST   | Yes           | Grant consent        |
| `/auth/consent/revoke`     | POST   | Yes           | Revoke consent       |
| `/auth/consent/revoke-all` | POST   | Yes           | Revoke all (bulk)    |
| `/auth/consent`            | DELETE | Yes           | Delete all (GDPR)    |
| `/auth/consent`            | GET    | Yes           | List consents        |

### Consent Lifecycle States

```
┌─────────┐
│ No      │
│ Consent │
└────┬────┘
     │ Grant
     ▼
┌─────────┐     Revoke     ┌─────────┐
│ Active  ├───────────────►│ Revoked │
└────┬────┘                └─────────┘
     │ Expiry
     ▼
┌─────────┐
│ Expired │
└─────────┘
```

**State Transitions:**

- `No Consent → Active`: User grants consent
- `Active → Revoked`: User revokes consent
- `Active → Expired`: Time passes beyond ExpiresAt
- `Revoked → Active`: User re-grants consent (creates new record)
- `Expired → Active`: User re-grants consent (creates new record)

### Default Expiry Period

**MVP:** 1 year from grant date
**Future:** Configurable per purpose (e.g., login = 1 year, registry_check = 30 days)

---

## 6. Integration Requirements

### IR-1: Authentication Integration

All consent endpoints require valid bearer token:

1. Extract token from Authorization header
2. Validate token (call `authService.UserInfo()`)
3. Extract user ID from token
4. Use user ID for consent operations

### IR-2: Audit Integration

Emit audit events for:

- Consent granted (per purpose)
- Consent revoked (per purpose)
- Consent check failed (when Require() returns error)

**Audit Event Format:**

```go
audit.Event{
    ID:        uuid.New().String(),
    Timestamp: time.Now(),
    UserID:    userID,
    Action:    "consent_granted", // or "consent_revoked", "consent_check_failed"
    Purpose:   string(purpose),
    Decision:  "granted", // or "revoked", "denied"
    Reason:    "user_initiated",
}
```

### IR-3: Handler Integration

All handlers processing user data MUST call `Require()` before operations:

**Example:**

```go
// In handleRegistryCitizen
err := h.consentService.Require(ctx, userID, consent.ConsentPurposeRegistryCheck)
if err != nil {
    writeError(w, err)
    return
}
// Proceed with registry lookup
```

**Handlers requiring consent:**

- `handleRegistryCitizen` → ConsentPurposeRegistryCheck
- `handleRegistrySanctions` → ConsentPurposeRegistryCheck
- `handleVCIssue` → ConsentPurposeVCIssuance
- `handleDecisionEvaluate` → ConsentPurposeDecision

---

## 7. Security Requirements

### SR-1: Authorization

- Only authenticated users can grant/revoke/list their own consents
- Users cannot modify consents for other users
- Service methods must validate user ID matches token

### SR-2: Audit Trail

- All consent changes must be logged to audit system
- Audit logs must be immutable (append-only)
- Audit logs must include timestamp, user ID, purpose, action

### SR-3: Consent Enforcement

- Failed consent checks must return 403 Forbidden
- Operations requiring consent must fail fast (check consent first)
- No data processing should occur without valid consent

---

## 8. Observability Requirements

### Logging

**Events to Log:**

- Consent granted: `consent_granted` (audit)
- Consent revoked: `consent_revoked` (audit)
- Consent check passed: `consent_check_passed` (debug level)
- Consent check failed: `consent_check_failed` (audit + warning)

### Metrics

- Total consents granted (counter, labeled by purpose)
- Total consents revoked (counter, labeled by purpose)
- Active consents per user (gauge)
- Consent check failures (counter, labeled by purpose)
- Consent grant latency (histogram)

---

## 9. Testing Requirements

### Unit Tests

- [x] Test consent granting for valid purposes
- [x] Test consent renewal (grant twice for same purpose)
- [x] Test idempotent grants within 5-minute window (no update, no audit)
- [x] Test consent updates after 5-minute window expires (updates timestamps)
- [x] Test expired consent always updates regardless of time window
- [x] Test revoked consent always updates regardless of time window
- [x] Test consent revocation
- [x] Test `IsActive()` with various states
- [x] Test `Require()` with active consent
- [x] Test `Require()` with missing consent (returns error)
- [x] Test `Require()` with expired consent (returns error)
- [x] Test `Require()` with revoked consent (returns error)

### Integration Tests

- [x] Test grant → list → verify active
- [x] Test grant → revoke → verify revoked
- [x] Test grant → expire (forced) → verify expired → re-grant → verify ID reused
- [x] Test idempotency: immediate re-grant → verify no audit event, same timestamps
- [x] Test TTL extension: re-grant after 6 minutes → verify new timestamps, new audit event
- [x] Test revoke + immediate re-grant → verify timestamps updated despite time window
- [x] Test require consent before registry lookup
- [x] Test handler fails with 403 when consent missing

### Projection/Read Model (TR-6) Tests

- [ ] With projection store enabled (memory/redis), `Require()` serves reads from projection path and falls back gracefully on cache miss.
- [ ] Grant/Revoke emits projection updates and subsequent `Require()` reflects the change without extra canonical writes.
- [ ] Projection version conflicts are detected and resolved (retry or surfaced) without corrupting projection state.
- [ ] Metrics for projection hits/misses/lag are emitted.

### Manual Testing

```bash
# 1. Grant consent
curl -X POST http://localhost:8080/auth/consent \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"purposes": ["login", "registry_check", "vc_issuance"]}'

# Expected: {"granted": [...], "message": "Consent granted for 3 purposes"}

# 2. List consents
curl http://localhost:8080/auth/consent \
  -H "Authorization: Bearer $TOKEN"

# Expected: {"consents": [{"purpose": "login", "status": "active", ...}, ...]}

# 3. Revoke consent
curl -X POST http://localhost:8080/auth/consent/revoke \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"purposes": ["registry_check"]}'

# Expected: {"revoked": [{"purpose": "registry_check", ...}]}

# 4. Try operation without consent (should fail)
curl -X POST http://localhost:8080/registry/citizen \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"national_id": "123456789"}'

# Expected: 403 Forbidden {"error": "missing_consent", ...}

# 5. Re-grant consent
curl -X POST http://localhost:8080/auth/consent \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"purposes": ["registry_check"]}'

# 6. Retry operation (should succeed)
curl -X POST http://localhost:8080/registry/citizen \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"national_id": "123456789"}'

# Expected: 200 OK with citizen data
```

---

## 10. Implementation Steps

### Phase 1: Service Layer Enhancement (1-2 hours)

1. Update `ConsentService` in `internal/consent/service.go`
2. Implement `Grant()` with renewal logic
3. Implement `Revoke()` with idempotency
4. Implement `List()` with filtering
5. Enhance `Require()` with proper error types
6. Add audit event emission in each method

### Phase 2: HTTP Handlers (1-2 hours)

1. Implement `handleConsent`:
   - Extract user from token
   - Parse purposes array
   - Call service for each purpose
   - Emit audit events
   - Return granted list
2. Implement `handleConsentRevoke`:
   - Extract user from token
   - Parse purposes array
   - Call service for each purpose
   - Return revoked list
3. Implement `handleConsentList`:
   - Extract user from token
   - Parse query filters
   - Call service
   - Return consent list

### Phase 3: Integration with Other Handlers (1 hour)

1. Add consent checks to:
   - `handleRegistryCitizen`
   - `handleRegistrySanctions`
   - `handleVCIssue`
   - `handleDecisionEvaluate`
2. Each should call `Require()` before processing

### Phase 4: Testing (1-2 hours)

1. Unit tests for service methods
2. Integration tests for complete flows
3. Manual testing with curl
4. Negative testing (missing consent scenarios)

---

## 11. Acceptance Criteria

- [x] Users can grant consent for multiple purposes in one request
- [x] Users can revoke consent for specific purposes
- [x] Users can list all their consents with current status
- [x] Operations requiring consent fail with 403 when consent missing
- [x] Operations requiring consent succeed when consent is active
- [x] Expired consents are treated as missing consent
- [x] Revoked consents are treated as missing consent
- [x] All consent changes emit audit events (except idempotent requests)
- [x] Re-granting consent after revocation works correctly (reuses ID)
- [x] Consent renewal updates expiry date (if outside idempotency window)
- [x] **NEW**: Rapid repeated grants (< 5 min) are idempotent (no audit noise)
- [x] **NEW**: Session extension grants (≥ 5 min) update TTL and emit audit
- [x] **NEW**: Consent IDs are always reused (no duplicate records per user+purpose)
- [ ] **TR-6 (projection path):** When projections are enabled, `Require()` serves reads from the projection store with canonical fallback, maintains identical audit/error semantics, and exposes projection hit/miss/lag metrics.
- [x] Code passes `make test` and `make lint`

---

## 12. Dependencies & Blockers

### Dependencies

- PRD-001: Authentication & Session Management (for user extraction from token)
- `internal/consent/store_memory.go` - ✅ Already implemented
- `internal/audit` - ✅ Already implemented
- `pkg/errors` - ✅ Already implemented

### Potential Blockers

- None identified

---

## 13. Future Enhancements (Out of Scope)

- Per-purpose expiry configuration (different TTLs)
- Consent templates (predefined consent bundles)
- Consent delegation (parent consent for child)
- Consent evidence (proof of how consent was obtained)
- Consent version tracking (terms updated, re-consent required)
- Automatic consent expiry notifications
- Consent withdrawal grace period (30-day retention)
- Conditional consent (consent with restrictions)
- Cascading consent (purpose A requires purpose B)

---

## 14. Regulatory Considerations

### GDPR Compliance

- ✅ Consent is freely given (users can grant/revoke)
- ✅ Consent is specific (per purpose, not blanket)
- ✅ Consent is informed (purpose labels are clear)
- ✅ Consent is unambiguous (explicit grant action)
- ✅ Users can withdraw consent easily
- ✅ Audit trail proves consent at time of processing

### HIPAA Compliance

- ✅ Consent is documented
- ✅ Consent includes date and time
- ✅ Consent is revocable
- ✅ Audit trail maintained

---

## 15. References

- [GDPR Article 7: Conditions for consent](https://gdpr-info.eu/art-7-gdpr/)
- [GDPR Recital 32: Conditions for consent](https://gdpr-info.eu/recitals/no-32/)
- Tutorial: `docs/TUTORIAL.md` Section 2
- Architecture: `../engineering/architecture.md`
- Implementation: `internal/consent/service/service.go`
- Models: `internal/consent/models/models.go`
- Tests: `internal/consent/service/service_test.go`, `internal/consent/integration_test.go`

---

## Revision History

| Version | Date       | Author       | Changes                                          |
| ------- | ---------- | ------------ | ------------------------------------------------ |
| 1.0     | 2025-12-03 | Product Team | Initial PRD                                      |
| 1.1     | 2025-12-10 | Engineering  | Added 5-min idempotency window, ID reuse details |
| 1.2     | 2025-12-10 | Engineering  | Add TR-6 CQRS Read Model & Projection Store      |
| 1.23    | 2025-12-12 | Engineering  | Expand TR-6 with detail                          |
| 1.3     | 2025-12-17 | Engineering  | Add FR-2.1 revoke-all bulk endpoint              |
| 1.4     | 2025-12-17 | Engineering  | Add FR-2.2 delete-all GDPR erasure endpoint      |
