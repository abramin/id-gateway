# PRD-007: User Data Rights (GDPR Compliance)

**Status:** Implementation Required
**Priority:** P1 (High)
**Owner:** Engineering Team
**Last Updated:** 2025-12-13

---

## 1. Overview

### Problem Statement

GDPR grants users specific rights over their personal data:

- **Right to Access** (Article 15): Users can export all their data
- **Right to Erasure** (Article 17): Users can request data deletion ("Right to be Forgotten")

Credo must implement both endpoints to comply with GDPR.

### Goals

- Implement data export endpoint (covered in PRD-006)
- Implement data deletion endpoint
- Delete or pseudonymize user data across all stores
- Retain audit logs (legal requirement) while pseudonymizing identifiable info
- Provide confirmation of deletion

### Non-Goals

- Data portability to other systems (just JSON export)
- Partial deletion (all or nothing)
- Deletion grace period (immediate deletion)
- Data backup/recovery after deletion
- User identity verification beyond bearer token

---

## 2. User Stories

**As a** user
**I want to** export all my personal data
**So that** I can see what the system knows about me

**As a** user
**I want to** delete all my personal data
**So that** I can exercise my right to be forgotten

**As a** compliance officer
**I want to** retain audit logs even after data deletion
**So that** I can prove regulatory compliance

---

## 3. Functional Requirements

### FR-1: Data Export (Already covered in PRD-006)

See **PRD-006: Audit & Compliance** for `GET /me/data-export` implementation. The data-export service MUST fan out concurrent reads across audit, consent, session, VC, and registry cache stores using a shared `context.Context` (errgroup/waitgroup), surface the first error, and aggregate results in a deterministic order. HTTP handlers remain thin (parse/validate, call service, render); no business logic in handlers.

---

### FR-2: Data Deletion

**Endpoint:** `DELETE /me`

**Description:** Delete all personal data for the authenticated user, while retaining audit logs for compliance.

**Input:**

- Header: `Authorization: Bearer <token>`

**Output (Success - 200):**

```json
{
  "message": "All personal data has been deleted",
  "deleted_at": "2025-12-03T10:00:00Z",
  "deleted": [
    "user_profile",
    "sessions",
    "consents",
    "verifiable_credentials",
    "registry_cache"
  ],
  "retained": ["audit_logs"],
  "note": "Audit logs have been pseudonymized for compliance"
}
```

**Business Logic:**

1. Extract user from bearer token
2. Emit audit event: `data_deletion_requested`
3. **Delete from each store:**
   - UserStore: Delete user record
   - SessionStore: Delete all user sessions
   - ConsentStore: Revoke all consents (or delete records)
   - VCStore: Delete all issued credentials
   - RegistryCache: Clear all cached registry data for user
4. **Pseudonymize audit logs:**
   - Replace userID with hash(userID) in all audit events
   - Keep action, purpose, decision, reason (no PII)
5. Invalidate bearer token (optional: add to revocation list)
6. Return confirmation

**GDPR Compliance Notes:**

- **Audit logs retained:** Required for legal compliance (6 years retention for financial regulations)
- **Pseudonymization:** Hash user ID so events can't be linked back to individual
- **Immediate deletion:** No grace period (can be added later if needed)

**Error Cases:**

- 401 Unauthorized: Invalid bearer token
- 500 Internal Server Error: Deletion failed (partial delete should rollback or log)

---

## 4. What Gets Deleted vs Retained

### Deleted (PII removed):

| Store         | What's Deleted                   | Why                               |
| ------------- | -------------------------------- | --------------------------------- |
| UserStore     | User profile (email, name, etc.) | Contains PII                      |
| SessionStore  | All sessions for user            | Linked to identity                |
| ConsentStore  | All consent records              | Linked to identity                |
| VCStore       | All issued credentials           | Contains or references PII        |
| RegistryCache | All cached registry records      | Contains PII (name, DOB, address) |

### Retained (Pseudonymized):

| Store      | What's Retained  | Why                                  | How Pseudonymized                |
| ---------- | ---------------- | ------------------------------------ | -------------------------------- |
| AuditStore | All audit events | Legal requirement (prove compliance) | Replace userID with hash(userID) |

### Pseudonymization Strategy:

```go
func pseudonymizeUserID(userID string) string {
    h := sha256.Sum256([]byte(userID + "salt"))
    return fmt.Sprintf("pseudonym_%x", h[:8])
}
```

**Result:** `user_123` becomes `pseudonym_a1b2c3d4`, events remain but can't be linked to real user.

---

## 5. Technical Requirements

### TR-0: Data Export Orchestration (Service Layer)

- Provide a dedicated service method (not handler) that issues concurrent store reads (audit, consent, session, VC, registry cache) with shared context cancellation and per-source latency metrics.
- Collate results into a single export DTO; avoid leaking internal errors—map to domain errors before returning to handlers.
- Enforce consistent ordering of exported sections so clients receive stable payload shape even when store latency varies.

### TR-1: Store Interface Updates

**Add Delete Methods to Each Store:**

```go
// UserStore
DeleteUser(ctx context.Context, userID string) error

// SessionStore
DeleteSessionsByUser(ctx context.Context, userID string) error

// ConsentStore
DeleteByUser(ctx context.Context, userID string) error

// VCStore
DeleteByUser(ctx context.Context, userID string) error

// RegistryCacheStore
ClearUser(ctx context.Context, userID string) error

// AuditStore (NEW METHOD)
PseudonymizeUser(ctx context.Context, userID string, pseudonym string) error
```

### TR-2: Deletion Service

**Location:** `internal/platform/deletion_service.go` (new file)

```go
type DeletionService struct {
    userStore     auth.UserStore
    sessionStore  auth.SessionStore
    consentStore  consent.Store
    vcStore       vc.Store
    registryCache registry.RegistryCacheStore
    auditStore    audit.Store
}

func (s *DeletionService) DeleteUserData(ctx context.Context, userID string) error {
    // 1. Emit audit event BEFORE deletion
    // 2. Delete from each store
    // 3. Pseudonymize audit logs
    // 4. Return nil or error
}
```

### TR-3: HTTP Handler

**Location:** `internal/transport/http/handlers_me.go`

```go
func (h *Handler) handleDataDeletion(w http.ResponseWriter, r *http.Request) {
    // 1. Extract user from bearer token
    // 2. Call deletionService.DeleteUserData(userID)
    // 3. Return confirmation JSON
    // 4. Set status 200 (or 204 No Content)
}
```

### TR-4: SQL Query Patterns for Data Rights

**Objective:** Demonstrate SQL capabilities for GDPR data export and deletion operations.

**Query Patterns Required:**

- **UNION ALL for Comprehensive Data Export:** Aggregate user data from multiple tables:

  ```sql
  -- Export all user data in single query with source tracking
  SELECT 'profile' AS source, id, email, first_name, last_name, NULL AS purpose, created_at
  FROM users WHERE id = :user_id
  UNION ALL
  SELECT 'session' AS source, id, NULL, NULL, NULL, NULL, created_at
  FROM sessions WHERE user_id = :user_id
  UNION ALL
  SELECT 'consent' AS source, id, NULL, NULL, NULL, purpose, granted_at
  FROM consent_records WHERE user_id = :user_id
  UNION ALL
  SELECT 'credential' AS source, id, NULL, NULL, NULL, type, issued_at
  FROM verifiable_credentials WHERE user_id = :user_id
  ORDER BY created_at;
  ```

- **CTE for Cascade Deletion Verification:**

  ```sql
  WITH deletion_manifest AS (
    SELECT 'users' AS table_name, COUNT(*) AS row_count
    FROM users WHERE id = :user_id
    UNION ALL
    SELECT 'sessions', COUNT(*)
    FROM sessions WHERE user_id = :user_id
    UNION ALL
    SELECT 'consent_records', COUNT(*)
    FROM consent_records WHERE user_id = :user_id
    UNION ALL
    SELECT 'verifiable_credentials', COUNT(*)
    FROM verifiable_credentials WHERE user_id = :user_id
    UNION ALL
    SELECT 'registry_cache', COUNT(*)
    FROM registry_cache WHERE user_id = :user_id
  )
  SELECT table_name, row_count
  FROM deletion_manifest
  WHERE row_count > 0;
  ```

- **Transactional Cascade Delete with Foreign Key Awareness:**

  ```sql
  BEGIN;
  -- Delete in correct order respecting foreign key constraints
  DELETE FROM registry_cache WHERE user_id = :user_id;
  DELETE FROM verifiable_credentials WHERE user_id = :user_id;
  DELETE FROM consent_records WHERE user_id = :user_id;
  DELETE FROM sessions WHERE user_id = :user_id;
  DELETE FROM users WHERE id = :user_id;
  COMMIT;
  ```

- **Pseudonymization with Window Function for Audit Logs:**

  ```sql
  -- Pseudonymize while preserving event ordering
  UPDATE audit_events
  SET user_id = :pseudonym,
      pseudonymized_at = NOW()
  WHERE user_id = :original_user_id
    AND id IN (
      SELECT id FROM audit_events
      WHERE user_id = :original_user_id
      ORDER BY timestamp
    );
  ```

- **Anti-Join to Find Orphaned Records:**

  ```sql
  -- Find consent records without valid users (data integrity check)
  SELECT c.id, c.user_id, c.purpose
  FROM consent_records c
  LEFT JOIN users u ON c.user_id = u.id
  WHERE u.id IS NULL;

  -- Alternative using NOT EXISTS (anti-join pattern)
  SELECT c.id, c.user_id, c.purpose
  FROM consent_records c
  WHERE NOT EXISTS (
    SELECT 1 FROM users u WHERE u.id = c.user_id
  );
  ```

- **Aggregate Export Statistics:**
  ```sql
  SELECT
    COUNT(*) FILTER (WHERE source = 'session') AS session_count,
    COUNT(*) FILTER (WHERE source = 'consent') AS consent_count,
    COUNT(*) FILTER (WHERE source = 'credential') AS credential_count,
    MIN(created_at) AS earliest_record,
    MAX(created_at) AS latest_record
  FROM (
    SELECT 'session' AS source, created_at FROM sessions WHERE user_id = :user_id
    UNION ALL
    SELECT 'consent', granted_at FROM consent_records WHERE user_id = :user_id
    UNION ALL
    SELECT 'credential', issued_at FROM verifiable_credentials WHERE user_id = :user_id
  ) combined;
  ```

**Database Design:**

- **Foreign Key Constraints:** All user-related tables reference `users(id)` with `ON DELETE CASCADE` or `ON DELETE RESTRICT` based on audit requirements
- **Partial Indexes:** `CREATE INDEX idx_active_consents ON consent_records (user_id) WHERE revoked_at IS NULL;`
- **Soft Delete Consideration:** For recovery window, use `deleted_at` timestamp instead of hard delete
- **Referential Integrity Check:** Constraint triggers to verify cascade completion

---

**SQL Indexing Enhancements (from "Use The Index, Luke"):**

**Pagination for Large Data Exports (Book Chapter 6):**

```sql
-- WHY THIS MATTERS: GDPR data export (GET /me/data-export) may return
-- thousands of events across multiple tables. Offset pagination is slow.
-- Seek (keyset) pagination is O(1) regardless of page number.

-- ANTI-PATTERN: Offset pagination (slow for large offsets)
SELECT * FROM audit_events
WHERE user_id = :uid
ORDER BY timestamp DESC
OFFSET 5000 LIMIT 100;
-- Problem: Scans and discards 5000 rows before returning 100
-- Page 50 is 50x slower than page 1

-- SOLUTION: Seek (keyset) pagination
SELECT * FROM audit_events
WHERE user_id = :uid
  AND timestamp < :last_seen_timestamp  -- Seek to position
ORDER BY timestamp DESC
LIMIT 100;
-- Uses index to jump directly; O(1) per page

-- For UNION ALL export across tables, paginate per-table:
WITH user_data AS (
  -- Page through each table separately with seek
  SELECT 'session' AS source, id, created_at
  FROM sessions
  WHERE user_id = :uid AND created_at < :last_session_ts
  ORDER BY created_at DESC LIMIT 50
  UNION ALL
  SELECT 'consent' AS source, id, granted_at
  FROM consent_records
  WHERE user_id = :uid AND granted_at < :last_consent_ts
  ORDER BY granted_at DESC LIMIT 50
  -- ... more tables
)
SELECT * FROM user_data ORDER BY created_at DESC LIMIT 100;
```

**Covering Index for Export Queries:**

```sql
-- WHY THIS MATTERS: Export queries fetch specific columns repeatedly.
-- Covering index avoids heap access for frequently exported fields.

-- Data export only needs key fields, not full record:
CREATE INDEX idx_sessions_export ON sessions (user_id, created_at)
  INCLUDE (id, status, ip_hash);

-- Export query becomes index-only scan:
SELECT id, created_at, status, ip_hash
FROM sessions
WHERE user_id = :uid
ORDER BY created_at DESC
LIMIT 100;

-- EXPLAIN shows: Index Only Scan (no heap fetches)
```

**Batch Deletion with Index Scan:**

```sql
-- WHY THIS MATTERS: CASCADE DELETE on large tables can be slow.
-- Batch deletion with indexed lookup is faster and doesn't lock table.

-- Index for deletion (if not using CASCADE):
CREATE INDEX idx_sessions_user ON sessions (user_id);
CREATE INDEX idx_consents_user ON consent_records (user_id);

-- Batch delete with LIMIT to avoid long transactions:
DELETE FROM sessions
WHERE ctid IN (
    SELECT ctid FROM sessions
    WHERE user_id = :uid
    LIMIT 1000
);
-- Repeat until no rows deleted

-- EXPLAIN should show: Index Scan on idx_sessions_user
-- NOT: Seq Scan on sessions
```

---

**Acceptance Criteria (SQL):**

- [ ] Data export uses UNION ALL to aggregate from all user tables
- [ ] Deletion manifest uses CTE to count affected rows before deletion
- [ ] Cascade deletes respect foreign key order or use ON DELETE CASCADE
- [ ] Audit pseudonymization preserves event ordering with window functions
- [ ] Orphan detection uses anti-join patterns (LEFT JOIN WHERE NULL or NOT EXISTS)
- [ ] Export statistics use aggregate functions with FILTER clause
- [ ] **NEW:** Data export uses seek pagination, not offset
- [ ] **NEW:** Export queries show Index Only Scan on covering indexes
- [ ] **NEW:** Batch deletion uses indexed lookup, not sequential scan

---

## 6. Implementation Steps

### Phase 1: Add Delete Methods to Stores (2-3 hours)

1. Update each store interface with Delete method
2. Implement in InMemory stores:
   - `InMemoryUserStore.DeleteUser()` - remove from map
   - `InMemorySessionStore.DeleteSessionsByUser()` - iterate and delete
   - `InMemoryConsentStore.DeleteByUser()` - iterate and delete
   - `InMemoryVCStore.DeleteByUser()` - iterate and delete
   - `InMemoryRegistryCache.ClearUser()` - remove cached records
3. Add `AuditStore.PseudonymizeUser()`:
   - Iterate all events for userID
   - Replace userID with pseudonym
   - Keep all other fields intact

### Phase 2: Implement DeletionService (1-2 hours)

1. Create `internal/platform/deletion_service.go`
2. Implement `DeleteUserData()`:
   - Emit `data_deletion_requested` audit event
   - Call delete on each store
   - Handle errors (log and continue? or rollback?)
   - Pseudonymize audit logs
   - Return success/error

### Phase 3: Implement handleDataDeletion (1 hour)

1. Update `internal/transport/http/handlers_me.go`
2. Extract user from token
3. Call deletionService
4. Return JSON confirmation

### Phase 4: Testing (1-2 hours)

1. Create user, perform various operations
2. Call DELETE /me
3. Verify all user data deleted
4. Verify audit logs retained but pseudonymized
5. Verify subsequent auth fails (user doesn't exist)

---

## 7. Acceptance Criteria

- [ ] Users can delete all their personal data via DELETE /me
- [ ] User profile, sessions, consents, VCs, cache are deleted
- [ ] Audit logs are retained but user IDs pseudonymized
- [ ] Deletion emits audit event before deleting
- [ ] After deletion, user cannot authenticate (user doesn't exist)
- [ ] Deletion confirmation includes what was deleted/retained
- [ ] Code passes tests and lint
- [ ] Integration test covers full deletion flow

---

## 8. Testing

```bash
# 1. Create user and perform operations
curl -X POST http://localhost:8080/auth/authorize -d '{"email": "deleteme@example.com", "client_id": "demo"}'
# Save session_id and get token

curl -X POST http://localhost:8080/auth/consent -H "Authorization: Bearer $TOKEN" -d '{"purposes": ["registry_check"]}'
curl -X POST http://localhost:8080/vc/issue -H "Authorization: Bearer $TOKEN" -d '{"type": "AgeOver18", "national_id": "123456789"}'

# 2. Verify data exists
curl http://localhost:8080/auth/userinfo -H "Authorization: Bearer $TOKEN"
# Expected: User profile returned

curl http://localhost:8080/me/data-export -H "Authorization: Bearer $TOKEN"
# Expected: Multiple audit events

# 3. Delete all data
curl -X DELETE http://localhost:8080/me \
  -H "Authorization: Bearer $TOKEN"

# Expected: {"message": "All personal data has been deleted", "deleted": [...], "retained": ["audit_logs"]}

# 4. Verify data deleted
curl http://localhost:8080/auth/userinfo -H "Authorization: Bearer $TOKEN"
# Expected: 401 Unauthorized (user no longer exists)

# 5. Verify audit logs retained (as admin, not implemented in MVP)
# Audit events should exist but with pseudonymized user IDs
```

---

## 9. Edge Cases & Error Handling

### Edge Case 1: Partial Deletion Failure

**Scenario:** User deleted from UserStore, but ConsentStore.Delete() fails.

**Solution:**

- Log error but continue (eventual consistency)
- OR: Implement transaction/rollback (more complex)
- **MVP:** Continue and log errors

### Edge Case 2: User Already Deleted

**Scenario:** DELETE /me called twice.

**Solution:** Idempotent - return success even if user doesn't exist.

### Edge Case 3: Active Sessions After Deletion

**Scenario:** User has multiple sessions, one is used after deletion request.

**Solution:**

- Delete all sessions immediately
- Subsequent requests with old tokens fail (user not found)
- **MVP:** No token revocation list needed

---

## 10. Future Enhancements

- Deletion grace period (30 days to undo)
- Soft delete (mark deleted, purge later)
- Deletion audit report (detailed list of what was deleted)
- Admin override (prevent deletion for compliance investigation)
- Deletion verification email (confirm before deleting)
- Data export before deletion (automatically send export before deleting)
- Backup retention policy (keep backups separate from live data)

---

## 11. GDPR Compliance Notes

### Article 17 - Right to Erasure (Right to be Forgotten)

✅ **User can request deletion** - DELETE /me endpoint
✅ **Deletion is prompt** - Immediate, no delay
✅ **Deletion is complete** - All personal data removed
⚠️ **Exceptions apply** - Audit logs retained for legal compliance (GDPR Article 17(3)(e): "for compliance with legal obligation")

### Article 15 - Right of Access

✅ **User can export data** - GET /me/data-export (PRD-006)
✅ **Export is comprehensive** - Includes all audit events
✅ **Export is machine-readable** - JSON format

---

## 12. References

- [GDPR Article 17: Right to erasure](https://gdpr-info.eu/art-17-gdpr/)
- [GDPR Article 15: Right of access](https://gdpr-info.eu/art-15-gdpr/)
- Tutorial: `docs/TUTORIAL.md` Section 7
- Existing Code: `internal/transport/http/handlers_me.go`

---

## Revision History

| Version | Date | Author | Changes |
| ------- | ---- | ------ | ------- |

<<<<<<< HEAD
| 1.3 | 2025-12-21 | Engineering | Enhanced TR-4: Added seek pagination, covering indexes, batch deletion patterns |
=======

> > > > > > > b731cdb (update prds with sql practice)
> > > > > > > | 1.2 | 2025-12-21 | Engineering | Added TR-4: SQL Query Patterns (UNION ALL, CTEs, cascade deletes, anti-joins, FK constraints) |
> > > > > > > | 1.1 | 2025-12-13 | Engineering | Specify concurrent data-export fan-out, add service-layer orchestration TR, handler stays thin |
> > > > > > > | 1.0 | 2025-12-03 | Product Team | Initial PRD |
