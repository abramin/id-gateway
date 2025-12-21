# PRD-028: Performance & Throughput Enhancements (Auth + Token Plane)

**Status:** Draft v0
**Priority:** P0 (Critical)
**Owner:** Engineering Team
**Dependencies:** PRD-001 (Authentication), PRD-016 (Token Lifecycle)

---

## 1. Overview

### Problem Statement

Auth and token flows are functionally complete (PRD-001/016) but lack performance safeguards for scale: redundant store hits on hot paths, no local caches, no background cleanup of expired sessions/tokens, and limited observability of latency regressions. We need a focused optimization pass to keep login/token endpoints sub-100ms p95 under load while avoiding data races and preserving correctness.

### Goals

- Reduce steady-state latency for `/auth/authorize`, `/auth/token`, and `/auth/userinfo`.
- Introduce concurrency-safe, bounded caches for sessions/tokens to offload primary stores.
- Move cleanup/revocation sweeps to background workers with graceful shutdown.
- Protect stores from bursty traffic via pooling and backpressure.
- Add performance observability (latency, cache hit rate, queue depth).

### Non-Goals

- No protocol changes to auth/token flows (remain compatible with PRD-001/016 contracts).
- No new authentication factors (handled by other PRDs).
- No persistence model changes; optimize current in-memory/mock stores.

---

## 2. Functional Requirements

### FR-1: Hot Path Latency Budget

- `/auth/authorize`, `/auth/token`, `/auth/userinfo` p95 < 100ms in-memory; p99 < 200ms under 200 RPS.
- No synchronous calls to slow dependencies on these paths; reuse client pools and caches.

### FR-2: Session/Token Read Cache

- Add per-process, concurrency-safe caches (LRU or TTL) for session lookups and token validations with bounded size and eviction metrics.
- Cache entries keyed by `session_id` and `refresh_token` hashes; validate TTL against underlying store version to avoid stale reuse.

### FR-3: Background Sweeper

- Run a background worker (goroutine) that sweeps expired sessions/tokens at a configurable interval; respects `context.Context` for shutdown and avoids blocking request paths.
- On shutdown, worker flushes pending revocations and exits cleanly (no goroutine leaks).

### FR-4: Store Access Pooling

- Reuse store/client connections (HTTP/DB) with tuned pool sizes and timeouts to avoid per-request setup cost.
- Apply bounded work queues for high-volume endpoints to shed load gracefully rather than overloading stores.

### FR-5: Performance Observability

- Emit metrics: per-endpoint latency histograms, cache hit/miss counts, sweeper duration, queue depth, pool saturation.
- Emit traces around cache miss → store fetch paths; annotate with cache outcome and pool wait time.

---

## 3. Technical Requirements

- Caches must be lock-protected or use atomic maps; no global mutable state without synchronization.
- Handler logic stays thin (parse/validate → call services). Services own cache lookups, store access, and error mapping.
- Background sweepers run with `context.Context`, stop on cancel, and log/metric their final flush counts.
- Provide configuration flags for cache size/TTL, sweeper interval, pool sizes, and queue capacity; defaults safe for single-node demo.
- Expose a lightweight health/debug endpoint showing cache stats and sweeper last-run time (non-PII).

### TR-6: SQL Indexing for Performance Optimization

**Objective:** Demonstrate SQL indexing concepts from "Use The Index, Luke" with production-ready patterns for auth/token performance.

**Topics Covered:**
- Function-based indexes (case-insensitive email lookups)
- Index combination limitations (why single multi-column beats multiple)
- Covering indexes (cache validation without heap access)
- EXPLAIN ANALYZE for p95 latency validation

---

#### Index Design

| Table | Index | Type | Columns | Purpose |
|-------|-------|------|---------|---------|
| `users` | `idx_users_email_lower` | B-Tree (function) | `(LOWER(email))` | Case-insensitive email lookup |
| `sessions` | `idx_sessions_user_status` | B-Tree | `(user_id, status)` | User's active sessions |
| `sessions` | `idx_sessions_covering` | B-Tree | `(session_id) INCLUDE (user_id, expires_at, status)` | Cache validation |
| `refresh_tokens` | `idx_tokens_hash_active` | B-Tree | `(token_hash, revoked_at)` | Token validation |
| `auth_codes` | `idx_codes_code_expires` | B-Tree | `(code, expires_at)` | Authorization code exchange |

---

#### Query Patterns with WHY

**Pattern 1: Function-Based Index for Case-Insensitive Email (Book Chapter 2.4)**

```sql
-- WHY THIS MATTERS: Email addresses are case-insensitive (user@example.com = USER@EXAMPLE.COM).
-- Without a function-based index, queries must scan entire table or use ILIKE (slow).

-- ANTI-PATTERN: ILIKE or LOWER() without index
SELECT * FROM users WHERE email ILIKE 'user@example.com';  -- Full table scan
SELECT * FROM users WHERE LOWER(email) = LOWER('user@example.com');  -- Full table scan

-- SOLUTION: Function-based index on LOWER(email)
CREATE INDEX idx_users_email_lower ON users (LOWER(email));

-- Query MUST match the index function exactly:
SELECT * FROM users WHERE LOWER(email) = LOWER(:email);

-- EXPLAIN should show: Index Scan on idx_users_email_lower
-- NOT: Seq Scan on users

-- CAUTION: The query function MUST match the index function exactly
-- This works:    WHERE LOWER(email) = LOWER('Test@Example.com')
-- This FAILS:    WHERE email ILIKE 'test@example.com'  -- Different function!
```

**Pattern 2: Index Combination Limitations (Book Chapter 3.3)**

```sql
-- WHY THIS MATTERS: PostgreSQL typically uses only ONE index per table scan.
-- Multiple single-column indexes are LESS efficient than one multi-column index.

-- ANTI-PATTERN: Multiple single-column indexes hoping for combination
CREATE INDEX idx_sessions_user ON sessions (user_id);
CREATE INDEX idx_sessions_status ON sessions (status);

-- Query that filters on both columns:
SELECT * FROM sessions WHERE user_id = :uid AND status = 'active';

-- PostgreSQL MIGHT use Bitmap Index Scan to combine, but:
-- 1. Bitmap scans are slower than single index scan
-- 2. Not guaranteed to use both indexes
-- 3. Extra memory for bitmap creation

-- SOLUTION: Single multi-column index
CREATE INDEX idx_sessions_user_status ON sessions (user_id, status);

-- Now the query uses one efficient index scan
-- EXPLAIN shows: Index Scan on idx_sessions_user_status

-- COLUMN ORDER MATTERS:
-- (user_id, status) serves: WHERE user_id = ?
--                          WHERE user_id = ? AND status = ?
-- Does NOT serve efficiently: WHERE status = ?  (would need leading column)
```

**Pattern 3: Covering Index for Cache Validation (Book Chapter 5)**

```sql
-- WHY THIS MATTERS: Session cache validation only needs existence + metadata.
-- Fetching full session row is wasteful. Covering index avoids heap access.

-- Session validation query (called on every authenticated request):
SELECT user_id, expires_at, status
FROM sessions
WHERE session_id = :sid;

-- Standard index requires heap fetch for user_id, expires_at, status:
CREATE INDEX idx_sessions_sid ON sessions (session_id);
-- EXPLAIN shows: Index Scan + Heap Fetches

-- COVERING index includes all needed columns:
CREATE INDEX idx_sessions_covering ON sessions (session_id)
  INCLUDE (user_id, expires_at, status);

-- Now EXPLAIN shows: Index Only Scan (0 heap fetches)
-- This is critical for p95 < 100ms target on hot auth paths

-- Calculate size overhead:
-- Standard: ~24 bytes per entry (just session_id)
-- Covering: ~56 bytes per entry (+user_id, expires_at, status)
-- Trade-off: 2.3x index size for ~40% query speedup
```

**Pattern 4: Efficient Token Lookup with Composite Key**

```sql
-- WHY THIS MATTERS: Token validation checks both token_hash AND revoked_at.
-- Order matters: token_hash is equality, revoked_at is NULL check.

-- Token validation query:
SELECT * FROM refresh_tokens
WHERE token_hash = :hash AND revoked_at IS NULL;

-- Composite index with equality column first:
CREATE INDEX idx_tokens_valid ON refresh_tokens (token_hash, revoked_at);

-- For partial index approach (only unrevoked tokens):
CREATE INDEX idx_tokens_active ON refresh_tokens (token_hash)
  WHERE revoked_at IS NULL;

-- Active tokens partial index is smaller:
-- Full index: indexes ALL tokens (including revoked)
-- Partial index: only indexes unrevoked tokens (~50% smaller typically)
```

**Pattern 5: Measuring p95/p99 with EXPLAIN ANALYZE**

```sql
-- WHY THIS MATTERS: PRD-028 requires p95 < 100ms, p99 < 200ms.
-- EXPLAIN ANALYZE measures actual execution time, not estimates.

-- Run query multiple times and capture timing:
EXPLAIN (ANALYZE, BUFFERS, TIMING)
SELECT user_id, expires_at, status FROM sessions WHERE session_id = :sid;

-- Look for:
-- "Execution Time: X.XXX ms"
-- "Buffers: shared hit=N read=M"  (reads = disk I/O, bad for latency)
-- "Index Only Scan" vs "Index Scan" (Index Only = no heap fetch)

-- Create a benchmark script:
\timing on
SELECT user_id FROM sessions WHERE session_id = 'test-sid-1';
SELECT user_id FROM sessions WHERE session_id = 'test-sid-2';
-- ... repeat 100 times

-- Calculate percentiles from timing output
-- p95 = 95th percentile of execution times
```

---

#### EXPLAIN ANALYZE Evidence Requirements

- [ ] `users` email lookup shows Index Scan on function-based index (LOWER(email))
- [ ] `sessions` query uses single composite index, not bitmap combination
- [ ] Session validation shows Index Only Scan (0 heap fetches)
- [ ] Token validation uses partial index for active tokens
- [ ] Auth endpoint latency <100ms p95 verified with EXPLAIN ANALYZE timing

---

#### Exercises

**Exercise 1: Function-Based Index Trap**
```sql
-- Setup
CREATE TABLE users_test (id SERIAL, email VARCHAR(255));
INSERT INTO users_test (email) SELECT 'user' || i || '@example.com' FROM generate_series(1, 100000) i;
CREATE INDEX idx_email_lower ON users_test (LOWER(email));

-- Test different query forms:
EXPLAIN ANALYZE SELECT * FROM users_test WHERE LOWER(email) = LOWER('USER50000@EXAMPLE.COM');
EXPLAIN ANALYZE SELECT * FROM users_test WHERE email ILIKE 'user50000@example.com';

-- Question: Which uses the index? Why does ILIKE fail?
-- Answer: ILIKE is a pattern match, not a function call. Index only works with LOWER().
```

**Exercise 2: Single vs Multiple Indexes**
```sql
-- Setup
CREATE TABLE sessions_test (id SERIAL, user_id INT, status VARCHAR(20));
INSERT INTO sessions_test (user_id, status) SELECT i % 1000, CASE WHEN random() > 0.7 THEN 'expired' ELSE 'active' END FROM generate_series(1, 100000) i;

-- Create two single indexes
CREATE INDEX idx_user ON sessions_test (user_id);
CREATE INDEX idx_status ON sessions_test (status);

-- Query with both filters
EXPLAIN ANALYZE SELECT * FROM sessions_test WHERE user_id = 500 AND status = 'active';
-- Note: Bitmap Heap Scan with two Bitmap Index Scans

-- Replace with composite
DROP INDEX idx_user;
DROP INDEX idx_status;
CREATE INDEX idx_user_status ON sessions_test (user_id, status);

EXPLAIN ANALYZE SELECT * FROM sessions_test WHERE user_id = 500 AND status = 'active';
-- Note: Single Index Scan - faster!
```

**Exercise 3: Covering Index Heap Fetch Reduction**
```sql
-- Setup
CREATE TABLE sessions_bench (session_id UUID PRIMARY KEY, user_id UUID, expires_at TIMESTAMPTZ, status VARCHAR(20));
INSERT INTO sessions_bench SELECT gen_random_uuid(), gen_random_uuid(), NOW() + (random() * 3600 || ' seconds')::interval, 'active' FROM generate_series(1, 100000);

-- Standard index
CREATE INDEX idx_sid ON sessions_bench (session_id);
EXPLAIN (ANALYZE, BUFFERS) SELECT user_id, expires_at FROM sessions_bench WHERE session_id = (SELECT session_id FROM sessions_bench LIMIT 1);
-- Note: Heap Fetches count

-- Covering index
DROP INDEX idx_sid;
CREATE INDEX idx_sid_covering ON sessions_bench (session_id) INCLUDE (user_id, expires_at, status);
EXPLAIN (ANALYZE, BUFFERS) SELECT user_id, expires_at FROM sessions_bench WHERE session_id = (SELECT session_id FROM sessions_bench LIMIT 1);
-- Note: Heap Fetches: 0
```

---

#### Acceptance Criteria (SQL)

- [ ] Email lookup uses function-based index on LOWER(email)
- [ ] Session queries use single composite index, not bitmap index combination
- [ ] Session validation achieves Index Only Scan (0 heap fetches)
- [ ] Token validation uses partial index for unrevoked tokens
- [ ] All auth hot path queries verified <100ms p95 with EXPLAIN ANALYZE
- [ ] Index size overhead documented and within acceptable bounds

---

## 4. Acceptance Criteria

- [ ] p95/p99 latency targets met for auth/token endpoints under specified load.
- [ ] Session/token caches show hit rates and bounded memory; eviction metrics available.
- [ ] Background sweeper runs on interval, stops cleanly on shutdown, and removes expired sessions/tokens.
- [ ] No business logic in handlers; services own caching/orchestration; internal errors not leaked to clients.
- [ ] Metrics/traces include cache hit/miss, pool wait time, sweeper runtime.

---

## 5. Dependencies & Risks

- Depends on PRD-001/016 contracts for token/session schemas.
- Risk: stale cache entries causing incorrect auth decisions; mitigated via TTL + store version checks.
- Risk: sweeper running too aggressively and contending with request paths; mitigated via configurable intervals and low-priority execution.

---

## Revision History

| Version | Date       | Author      | Changes                                                                                       |
| ------- | ---------- | ----------- | --------------------------------------------------------------------------------------------- |
| 1.1     | 2025-12-21 | Engineering | Added TR-6: SQL Indexing for Performance (function-based, covering indexes, index combination) |
| 1.0     | 2025-12-16 | Engineering | Initial draft for perf pass on auth/token plane                                               |
