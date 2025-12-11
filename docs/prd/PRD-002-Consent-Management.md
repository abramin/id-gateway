# PRD-002: Consent Management System

**Status:** Implementation Required
**Priority:** P0 (Critical)
**Priority:** P0 (Critical)
**Owner:** Engineering Team
**Last Updated:** 2025-12-03

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

### TR-6: CQRS Read Model & Projection Store

**Objective:** Separate the high-volume "has consent?" reads from write-heavy grant/revoke flows using a dedicated read model ba
cked by a low-latency NoSQL/TTL store.

**Projection Contents:**
- Key: `user_id:purpose`
- Value: `{status: active|revoked|expired, expires_at, revoked_at, version}`

**Write Path Responsibilities:**
- Consent service writes canonical records to `ConsentStore` (SQL/in-memory) and emits change events to the audit/event bus.
- A projection worker consumes these events and updates the read model idempotently (version checks to avoid stale writes).

**Read Path Responsibilities:**
- `Require` calls and other services first read from the projection store (Redis/DynamoDB/Mongo) for sub-5ms lookups; cache
  misses trigger fallback to `ConsentStore` and projection refresh.
- Projection lag budget: ≤1s; on stale reads, downstream can re-validate via canonical store.

**Resilience & Ops:**
- Provide a replay tool to rebuild the projection from the append-only audit log.
- Support in-memory projection implementation for local/dev while keeping interfaces identical to production NoSQL/Redis.

---

## 5. API Specifications

### Endpoint Summary

| Endpoint               | Method | Auth Required | Purpose        |
| ---------------------- | ------ | ------------- | -------------- |
| `/auth/consent`        | POST   | Yes           | Grant consent  |
| `/auth/consent/revoke` | POST   | Yes           | Revoke consent |
| `/auth/consent`        | GET    | Yes           | List consents  |

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
- Architecture: `docs/architecture.md`
- Implementation: `internal/consent/service/service.go`
- Models: `internal/consent/models/models.go`
- Tests: `internal/consent/service/service_test.go`, `internal/consent/integration_test.go`

---

## Revision History

| Version | Date       | Author       | Changes                                          |
| ------- | ---------- | ------------ | ------------------------------------------------ |
| 1.0     | 2025-12-03 | Product Team | Initial PRD                                      |
| 1.1     | 2025-12-10 | Engineering  | Added 5-min idempotency window, ID reuse details |
