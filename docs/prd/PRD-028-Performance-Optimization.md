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

| Version | Date       | Author      | Changes                                         |
| ------- | ---------- | ----------- | ----------------------------------------------- |
| 1.0     | 2025-12-16 | Engineering | Initial draft for perf pass on auth/token plane |
