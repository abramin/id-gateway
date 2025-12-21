# PRD-006: Audit & Compliance Logging

**Status:** Implementation Required
**Priority:** P0 (Critical)
**Owner:** Engineering Team
**Last Updated:** 2025-12-18

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

**Description:** Internal service method called by handlers to log sensitive operations. MUST be non-blocking using a buffered channel + background worker started at server bootstrap with graceful shutdown on context cancel.

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

**Outline:**

- Publisher owns a bounded channel (size configurable) and a worker goroutine that persists events to the store.
- `Emit` performs a non-blocking enqueue with backpressure policy: drop oldest or block based on configuration; emit metrics for drops/queue depth.
- Worker runs with `context.Context`, drains the channel, and flushes outstanding events on shutdown; emits span/metric annotations for latency and failures.
- `List` remains a synchronous store read.

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

### TR-5: Secure Audit Storage & Integrity

- Append-only log with hash chaining per partition (e.g., daily partition); store chain heads separately for integrity verification.
- Database requirements: partitioned tables by day/week with covering indexes on `(actor/user_id, action, timestamp)`; `EXPLAIN` plans must be documented.
- Enforce write-once (no update/delete) at the storage layer (e.g., Postgres CHECKs/triggers) and require WORM-capable storage for exported archives.
- Ingest path validates event schema and rejects missing correlation IDs/subjects; default deny on malformed events.
- Reader interfaces are split: `AuditAppender` (write-only) and `AuditReader` (read-scoped per subject/tenant) to enforce least privilege.
- Periodic anchoring of partition roots; verification APIs must prove inclusion/consistency against anchored roots.

### TR-5: Event Streaming & Indexing Pipeline

- **Transport:** Publish audit events to Kafka/NATS topics so ingestion is decoupled from request latency; keep the synchronous
  store append as a fallback for degraded modes.
- **Indexing Workers:** Dedicated consumers forward events to Elasticsearch/OpenSearch indices (per-day) and a long-term
  warehouse/object store. Include dead-letter handling for indexing errors.
- **Reliability:** Use an outbox pattern on emitters to guarantee delivery into Kafka; projection/indexers should be
  idempotent using event IDs and versions.
- **Caching:** Permit a Redis cache for hot investigative queries (recent 24h) to accelerate compliance dashboards; cache
  invalidations are driven by Kafka consumer offsets so caches stay consistent with the index.

### TR-6: SQL Query Patterns & Database Design

**Objective:** Demonstrate intermediate-to-advanced SQL capabilities for audit storage and compliance queries.

**Query Patterns Required:**

- **CTEs for Event Chain Correlation:** Use CTEs to trace related audit events:
  ```sql
  WITH session_events AS (
    SELECT id, user_id, action, timestamp, request_id
    FROM audit_events
    WHERE request_id = :correlation_id
  ),
  user_journey AS (
    SELECT se.*,
           ROW_NUMBER() OVER (ORDER BY timestamp) AS step_num
    FROM session_events se
  )
  SELECT * FROM user_journey ORDER BY step_num;
  ```

- **Window Functions for Audit Analytics:** Use `LEAD()`, `LAG()`, sliding windows for pattern detection:
  ```sql
  SELECT user_id, action, timestamp,
         LEAD(action) OVER (PARTITION BY user_id ORDER BY timestamp) AS next_action,
         LAG(timestamp) OVER (PARTITION BY user_id ORDER BY timestamp) AS prev_timestamp,
         timestamp - LAG(timestamp) OVER (PARTITION BY user_id ORDER BY timestamp) AS time_delta,
         COUNT(*) OVER (
           PARTITION BY user_id
           ORDER BY timestamp
           RANGE BETWEEN INTERVAL '1 hour' PRECEDING AND CURRENT ROW
         ) AS actions_last_hour
  FROM audit_events
  WHERE timestamp > NOW() - INTERVAL '7 days';
  ```

- **Aggregate Functions with HAVING for Compliance Reports:**
  ```sql
  SELECT user_id,
         COUNT(*) AS total_events,
         COUNT(DISTINCT action) AS unique_actions,
         MIN(timestamp) AS first_event,
         MAX(timestamp) AS last_event,
         SUM(CASE WHEN decision = 'denied' THEN 1 ELSE 0 END) AS denied_count
  FROM audit_events
  WHERE timestamp BETWEEN :start_date AND :end_date
  GROUP BY user_id
  HAVING COUNT(*) > 100 OR SUM(CASE WHEN decision = 'denied' THEN 1 ELSE 0 END) > 5;
  ```

- **Set Operations for Cross-User Investigation:**
  ```sql
  -- Users who did both consent_granted and data_exported
  SELECT DISTINCT user_id FROM audit_events WHERE action = 'consent_granted'
  INTERSECT
  SELECT DISTINCT user_id FROM audit_events WHERE action = 'data_exported'

  EXCEPT

  -- Exclude users who subsequently revoked consent
  SELECT DISTINCT user_id FROM audit_events WHERE action = 'consent_revoked';
  ```

- **Correlated Subqueries for Event Comparison:**
  ```sql
  SELECT a.id, a.user_id, a.action, a.timestamp,
         (SELECT COUNT(*) FROM audit_events b
          WHERE b.user_id = a.user_id
            AND b.timestamp < a.timestamp) AS prior_event_count,
         EXISTS (SELECT 1 FROM audit_events c
                 WHERE c.user_id = a.user_id
                   AND c.action = 'consent_granted'
                   AND c.timestamp < a.timestamp) AS had_prior_consent
  FROM audit_events a
  WHERE a.action = 'decision_made';
  ```

- **Self-Join for Suspicious Pattern Detection (Semi-Join/Anti-Join):**
  ```sql
  -- Find users with rapid successive failed decisions (semi-join pattern)
  SELECT DISTINCT a1.user_id
  FROM audit_events a1
  WHERE EXISTS (
    SELECT 1 FROM audit_events a2
    WHERE a1.user_id = a2.user_id
      AND a1.id != a2.id
      AND a1.decision = 'denied' AND a2.decision = 'denied'
      AND ABS(EXTRACT(EPOCH FROM (a1.timestamp - a2.timestamp))) < 60
  );

  -- Find consent grants with no subsequent decision (anti-join pattern)
  SELECT c.user_id, c.purpose, c.timestamp
  FROM audit_events c
  WHERE c.action = 'consent_granted'
    AND NOT EXISTS (
      SELECT 1 FROM audit_events d
      WHERE d.user_id = c.user_id
        AND d.action = 'decision_made'
        AND d.timestamp > c.timestamp
    );
  ```

**Database Design:**

- **Partitioning Strategy:** Range partition by timestamp (daily/weekly partitions); use `pg_partman` for automated management
- **Covering Indexes:**
  - `(user_id, timestamp)` for user timeline queries
  - `(action, timestamp)` for action-based filtering
  - `(request_id)` for correlation lookups
- **Materialized Views:** Pre-aggregate daily/weekly compliance summaries:
  ```sql
  CREATE MATERIALIZED VIEW daily_audit_summary AS
  SELECT DATE(timestamp) AS audit_date,
         action,
         COUNT(*) AS event_count,
         COUNT(DISTINCT user_id) AS unique_users
  FROM audit_events
  GROUP BY DATE(timestamp), action
  WITH DATA;

  CREATE UNIQUE INDEX ON daily_audit_summary (audit_date, action);
  ```

- **WORM Storage Compliance:** Audit tables use `pg_dumpall` with append-only semantics; no UPDATE/DELETE triggers allowed

<<<<<<< HEAD
---

**SQL Indexing Enhancements (from "Use The Index, Luke"):**

**Partition Pruning for Time-Based Queries:**

```sql
-- WHY THIS MATTERS: Audit tables can grow to billions of rows.
-- Without partitioning, every query scans the entire table.
-- Range partitioning by timestamp enables partition pruning.

-- Create partitioned audit table:
CREATE TABLE audit_events (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    action VARCHAR(50) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    request_id UUID,
    details JSONB
) PARTITION BY RANGE (timestamp);

-- Monthly partitions:
CREATE TABLE audit_events_2025_01 PARTITION OF audit_events
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
CREATE TABLE audit_events_2025_02 PARTITION OF audit_events
    FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');
-- ... automated via pg_partman

-- Query with partition pruning:
EXPLAIN ANALYZE
SELECT * FROM audit_events
WHERE timestamp >= '2025-01-15' AND timestamp < '2025-01-20'
  AND user_id = :uid;

-- Expected: "Append" with only "audit_events_2025_01" scanned
-- NOT: All partitions scanned
```

**Pagination: Offset vs Seek Method (Book Chapter 6):**

```sql
-- WHY THIS MATTERS: Data export (GET /me/data-export) may return thousands of events.
-- Offset pagination degrades as page number increases.
-- Seek (keyset) pagination is O(1) regardless of page.

-- ANTI-PATTERN: Offset pagination
SELECT * FROM audit_events
WHERE user_id = :uid
ORDER BY timestamp DESC
OFFSET 10000 LIMIT 100;
-- PostgreSQL scans and discards 10,000 rows, then returns 100
-- Page 1000 is 10x slower than page 1

-- SOLUTION: Seek (keyset) pagination
SELECT * FROM audit_events
WHERE user_id = :uid
  AND timestamp < :last_seen_timestamp  -- Seek condition
ORDER BY timestamp DESC
LIMIT 100;
-- Uses index to jump directly to position; O(1) per page

-- For exact duplicate timestamps, use composite key:
SELECT * FROM audit_events
WHERE user_id = :uid
  AND (timestamp, id) < (:last_ts, :last_id)
ORDER BY timestamp DESC, id DESC
LIMIT 100;
-- Handles tie-breaker on duplicate timestamps
```

**Sort-Merge Join for Large Compliance Reports:**

```sql
-- WHY THIS MATTERS: Compliance reports may join audit_events with users or consents.
-- For large datasets, Sort-Merge Join can outperform Nested Loop.
-- PostgreSQL chooses automatically, but index on sort key helps.

-- Index supporting sort-merge:
CREATE INDEX idx_audit_user_time ON audit_events (user_id, timestamp);
CREATE INDEX idx_consent_user_time ON consent_records (user_id, granted_at);

-- Compliance report joining audit with consent:
EXPLAIN ANALYZE
SELECT a.user_id, a.action, a.timestamp, c.purpose, c.granted_at
FROM audit_events a
JOIN consent_records c
  ON a.user_id = c.user_id
  AND a.timestamp > c.granted_at
WHERE a.action = 'decision_made'
  AND a.timestamp BETWEEN '2025-01-01' AND '2025-02-01';

-- EXPLAIN may show: "Merge Join" when both sides are pre-sorted
-- Merge Join is efficient when:
-- 1. Both inputs are sorted on join key
-- 2. Output is also required sorted
-- 3. Large datasets (Hash Join needs memory)
```

**EXPLAIN ANALYZE Evidence for Audit Queries:**

```sql
-- Verify partition pruning:
EXPLAIN (ANALYZE, VERBOSE)
SELECT * FROM audit_events
WHERE timestamp >= '2025-01-01' AND timestamp < '2025-01-08'
  AND user_id = :uid;
-- Look for: "Partitions removed: X" or only one partition in Append

-- Verify seek pagination uses index:
EXPLAIN (ANALYZE, BUFFERS)
SELECT * FROM audit_events
WHERE user_id = :uid AND timestamp < '2025-01-15'
ORDER BY timestamp DESC LIMIT 100;
-- Look for: "Index Scan Backward"
-- NOT: "Seq Scan" or "Sort"

-- Verify compliance join:
EXPLAIN (ANALYZE, BUFFERS)
SELECT a.user_id, COUNT(*)
FROM audit_events a
JOIN consent_records c ON a.user_id = c.user_id
WHERE a.timestamp > c.granted_at
GROUP BY a.user_id;
-- Look for: "Merge Join" or "Hash Join" (appropriate for data size)
```

---

=======
>>>>>>> b731cdb (update prds with sql practice)
**Acceptance Criteria (SQL):**
- [ ] Event correlation uses CTEs with window functions
- [ ] Audit analytics use sliding window aggregations
- [ ] Compliance reports use GROUP BY/HAVING with aggregate filters
- [ ] Cross-user investigations use UNION/INTERSECT/EXCEPT
- [ ] Suspicious pattern detection uses semi-joins and anti-joins
- [ ] Partitioned tables verified with `EXPLAIN ANALYZE` showing partition pruning
- [ ] Materialized views for summaries with scheduled refresh
<<<<<<< HEAD
- [ ] **NEW:** Data export uses seek pagination, not offset
- [ ] **NEW:** Partition pruning verified (only relevant partitions scanned)
- [ ] **NEW:** Large compliance reports use appropriate join strategy (Merge/Hash)
=======
>>>>>>> b731cdb (update prds with sql practice)

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

- Replace in-process channel with queue-based transport (NATS, Kafka) and multi-consumer indexing workers
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

## Revision History

| Version | Date       | Author       | Changes                                                                                                     |
| ------- | ---------- | ------------ | ----------------------------------------------------------------------------------------------------------- |
<<<<<<< HEAD
| 1.7     | 2025-12-21 | Engineering  | Enhanced TR-6: Added partition pruning, seek pagination, sort-merge joins, EXPLAIN requirements             |
=======
>>>>>>> b731cdb (update prds with sql practice)
| 1.6     | 2025-12-21 | Engineering  | Added TR-6: SQL Query Patterns (CTEs, window functions, aggregates, set operations, semi/anti-joins, views) |
| 1.5     | 2025-12-18 | Security Eng | Added anchoring/verification requirements alongside partitioning and least-privilege interfaces             |
| 1.4     | 2025-12-18 | Security Eng | Added secure storage/integrity (hash chaining, partitioning, least-privilege interfaces)                    |
| 1.3     | 2025-12-16 | Engineering  | Formalize async publisher (buffered channel + worker, shutdown semantics, metrics/backpressure)             |
| 1.2     | 2025-12-12 | Engineering  | Add FR-3: Searchable Audit Queries (Investigations) & TR-5: Event Streaming & Indexing Pipeline             |
| 1.0     | 2025-12-03 | Product Team | Initial PRD                                                                                                 |
