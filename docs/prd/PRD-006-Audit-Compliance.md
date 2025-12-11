# PRD-006: Audit & Compliance Logging

**Status:** Implementation Required
**Priority:** P0 (Critical)
**Owner:** Engineering Team
**Last Updated:** 2025-12-03

---

## 1. Overview

### Problem Statement
Regulated systems must prove:
- **Who** accessed **whose** data
- **When** the access occurred
- **What** action was performed
- **Why** (for what purpose)
- **What decision** was made

This requires an **append-only**, **immutable**, **searchable** audit log.

### Goals
- Emit audit events for all sensitive operations
- Store events in append-only fashion (no updates/deletes)
- Provide audit export for users (GDPR transparency)
- Non-blocking event emission (async publishing)
- Support querying by user, action, time range
- Provide a searchable index (Elasticsearch/OpenSearch) for investigative queries with eventual consistency

### Non-Goals
- Real-time audit dashboards
- SIEM-grade correlation rules (can be exported later)
- Audit log retention policies (assume permanent for MVP)
- Audit log encryption at rest
- External audit log shipping (Splunk, Datadog)

---

## 2. Functional Requirements

### FR-1: Emit Audit Events (Internal API)

**Function:** `auditPublisher.Emit(ctx, event)`

**Description:** Internal service method called by handlers to log sensitive operations. Should be non-blocking.

**Usage Example:**
```go
_ = h.auditPublisher.Emit(ctx, audit.Event{
    ID:        uuid.New().String(),
    Timestamp: time.Now(),
    UserID:    userID,
    Action:    "consent_granted",
    Purpose:   "registry_check",
    Decision:  "granted",
    Reason:    "user_initiated",
    RequestID: r.Header.Get("X-Request-ID"),
})
```

**Events to Emit:**
| Action | When | Purpose |
|--------|------|---------|
| `auth_started` | User authorizes | login |
| `token_issued` | Tokens generated | login |
| `consent_granted` | Consent given | (specific purpose) |
| `consent_revoked` | Consent revoked | (specific purpose) |
| `registry_citizen_checked` | Citizen lookup | registry_check |
| `registry_sanctions_checked` | Sanctions lookup | sanctions_screening |
| `vc_issued` | Credential issued | vc_issuance |
| `vc_verified` | Credential verified | vc_verification |
| `decision_made` | Decision evaluated | (specific purpose) |
| `data_exported` | User exports data | data_access |
| `data_deleted` | User deletes data | data_deletion |

---

### FR-2: Export User Audit Log
**Endpoint:** `GET /me/data-export`

**Description:** Export all audit events for the authenticated user (GDPR Article 15 - Right to Access).

**Input:**
- Header: `Authorization: Bearer <token>`
- Query params (optional):
  - `from` - Start date (ISO 8601)
  - `to` - End date (ISO 8601)
  - `action` - Filter by action type

**Output (Success - 200):**
```json
{
  "user_id": "user_123",
  "export_date": "2025-12-03T10:00:00Z",
  "events": [
    {
      "id": "evt_abc123",
      "timestamp": "2025-12-03T09:00:00Z",
      "action": "auth_started",
      "purpose": "login",
      "decision": "granted",
      "reason": "user_initiated"
    },
    {
      "id": "evt_def456",
      "timestamp": "2025-12-03T09:05:00Z",
      "action": "consent_granted",
      "purpose": "registry_check",
      "decision": "granted",
      "reason": "user_initiated"
    },
    {
      "id": "evt_ghi789",
      "timestamp": "2025-12-03T09:10:00Z",
      "action": "decision_made",
      "purpose": "age_verification",
      "decision": "pass",
      "reason": "all_checks_passed"
    }
  ],
  "total": 3
}
```

---

### FR-3: Searchable Audit Queries (Investigations)

**Endpoint:** `GET /audit/search`

**Description:** Allow authorized compliance users to search audit events across users with filters. Backed by an Elasticsearch/
OpenSearch index fed from the append-only event stream.

**Input:**
- Query params:
  - `user_id` (optional)
  - `action` (optional, multi-value)
  - `purpose` (optional)
  - `from`, `to` (ISO timestamps)
  - `decision` (optional)
- Header: `Authorization: Bearer <token>` with `admin/compliance` role

**Output (Success - 200):**
```json
{
  "results": [
    {
      "id": "evt_def456",
      "timestamp": "2025-12-03T09:05:00Z",
      "user_id": "user_123",
      "action": "consent_granted",
      "purpose": "registry_check",
      "decision": "granted",
      "reason": "user_initiated"
    }
  ],
  "total": 1,
  "took_ms": 12
}
```

**Implementation Notes:**
- Events are appended to durable storage (object store or SQL) and streamed into Elasticsearch/OpenSearch for indexing.
- Index mappings should accommodate nested payloads and time-based indices for retention; daily indices acceptable for MVP.
- On query errors or index lag, fall back to exporting raw events (slower) but keep the API contract stable.

**Business Logic:**
1. Extract user from bearer token
2. Parse optional filters (from, to, action)
3. Call `auditStore.ListByUser(userID)`
4. Apply filters (date range, action)
5. Return events as JSON

**Error Cases:**
- 401 Unauthorized: Invalid bearer token
- 500 Internal Server Error: Store failure

---

## 3. Technical Requirements

### TR-1: Data Model

**Location:** `internal/audit/models.go`

```go
type Event struct {
    ID        string    // Unique event ID
    Timestamp time.Time // When event occurred
    UserID    string    // Subject user ID
    Action    string    // What happened (e.g., "consent_granted")
    Purpose   string    // Why (e.g., "registry_check")
    Decision  string    // Outcome (e.g., "granted", "pass", "fail")
    Reason    string    // Human-readable reason
    RequestID string    // Correlation ID for tracing
}
```

### TR-2: Publisher (Non-Blocking)

**Location:** `internal/audit/publisher.go`

```go
type Publisher struct {
    store Store
}

func (p *Publisher) Emit(ctx context.Context, ev Event) error {
    // Synchronous for MVP, async with channel in production
    return p.store.Append(ctx, ev)
}

func (p *Publisher) List(ctx context.Context, userID string) ([]Event, error) {
    return p.store.ListByUser(ctx, userID)
}
```

**Future:** Use buffered channel + background worker for async publishing.

### TR-3: Store (Append-Only)

**Location:** `internal/audit/store.go`

```go
type Store interface {
    Append(ctx context.Context, ev Event) error
    ListByUser(ctx context.Context, userID string) ([]Event, error)
    ListAll(ctx context.Context, limit, offset int) ([]Event, error)
    // NO Update() or Delete() - append-only
}
```

**Implementation:** `internal/audit/store_memory.go` (already exists)

### TR-4: HTTP Handler

**Location:** `internal/transport/http/handlers_me.go`

```go
func (h *Handler) handleDataExport(w http.ResponseWriter, r *http.Request) {
    // Extract user from token
    // Parse query filters
    // Call auditPublisher.List(userID)
    // Return JSON
}
```

---

## 4. Implementation Steps

1. **Phase 1:** Audit Integration Across Handlers (2-3 hours)
   - Add `auditPublisher.Emit()` calls to:
     - handleAuthorize
     - handleToken
     - handleConsent
     - handleConsentRevoke
     - handleRegistryCitizen
     - handleRegistrySanctions
     - handleVCIssue
     - handleVCVerify
     - handleDecisionEvaluate
   - Use appropriate action names and purposes

2. **Phase 2:** Implement handleDataExport (1 hour)
   - Extract user from token
   - Call auditPublisher.List()
   - Format as JSON
   - Return response

3. **Phase 3:** Testing (1 hour)
   - Perform full flow: auth → consent → VC → decision
   - Call /me/data-export
   - Verify all events appear
   - Test filtering (date range, action)

---

## 5. Acceptance Criteria

- [ ] All sensitive operations emit audit events
- [ ] Events include action, purpose, decision, reason
- [ ] Users can export their complete audit log
- [ ] Audit log is append-only (no updates/deletes)
- [ ] Event emission is non-blocking (doesn't slow handlers)
- [ ] Audit log survives server restarts (use store, not just logs)
- [ ] Code passes tests and lint

---

## 6. Testing

```bash
# Perform various operations
curl -X POST http://localhost:8080/auth/authorize -d '{"email": "alice@example.com", "client_id": "demo"}'
curl -X POST http://localhost:8080/auth/consent -H "Authorization: Bearer $TOKEN" -d '{"purposes": ["registry_check"]}'
curl -X POST http://localhost:8080/vc/issue -H "Authorization: Bearer $TOKEN" -d '{"type": "AgeOver18", "national_id": "123456789"}'

# Export audit log
curl http://localhost:8080/me/data-export \
  -H "Authorization: Bearer $TOKEN"

# Expected: Array of events with actions: auth_started, consent_granted, vc_issued, etc.

# Test filtering by action
curl "http://localhost:8080/me/data-export?action=consent_granted" \
  -H "Authorization: Bearer $TOKEN"

# Expected: Only consent_granted events
```

---

## 7. Future Enhancements

- Async event publishing (channel + worker goroutine)
- Queue-based audit (NATS, Kafka)
- Persistent store (Postgres, MongoDB)
- Audit log retention policies (delete after N years)
- Audit dashboards (real-time monitoring)
- External log shipping (Splunk, Datadog)
- Audit log encryption
- Audit log signing (tamper-proof)

---

## References
- [GDPR Article 15: Right of access](https://gdpr-info.eu/art-15-gdpr/)
- Tutorial: `docs/TUTORIAL.md` Section 6
- Existing Code: `internal/audit/`
