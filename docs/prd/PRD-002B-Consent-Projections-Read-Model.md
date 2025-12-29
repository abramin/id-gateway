# PRD-002B: Consent Projections & Read Models

**Status:** Not Started  
**Priority:** P1 (Performance)  
**Owner:** Engineering  
**Dependencies:** PRD-002, PRD-020  
**Last Updated:** 2025-12-27

---

## 1. Purpose

Move consent read traffic to a dedicated projection store to reduce contention
and keep `Require()` p95 under 5ms at high read/write ratios. This PRD
implements TR-6 deferred from PRD-002.

## 2. Scope

- Projection store interface + implementations (memory, Redis).
- Event publication on grant/revoke and a projection worker.
- Read path uses projection first with fallback to canonical store.
- Projection rebuild and GDPR delete hooks (user self-service and admin legal delete).
- Metrics for hit rate, lag, conflicts, and error rates.

## 3. Non-Scope

- New consent APIs or changes to consent semantics.
- Changes to audit event schemas.
- Replacing the canonical consent store.
- Changing permission boundaries or admin/user authorization flows (PRD-002, PRD-002C).

## 4. Functional Requirements

1. **Projection Store**
   - Keyed by `user_id + purpose`.
   - Stores status, expiry, revoked_at, and version.
   - Supports optimistic locking on updates.

2. **Eventing**
   - `ConsentChanged` event emitted on grant/revoke.
   - Event payload preserves `reason` and `actor_id` from the canonical path
     even if the projection does not use them for reads.
   - Worker applies events to projection store with retries.

3. **Read Path**
   - `Require()` checks projection first.
   - On miss or error, fallback to canonical store.
   - Behavior and error codes match the canonical path.

4. **Rebuild**
   - Projection rebuild from canonical store or event log.
   - GDPR delete triggers projection delete by user for both:
     - user self-service delete (`DELETE /auth/consent`)
     - admin legal delete (`DELETE /admin/consent/users/{user_id}`)

5. **Observability**
   - Metrics: hit/miss, lag seconds, conflicts, errors.
   - Alerts on lag > 5s or error rate > 1%.

6. **Per-Purpose Expiry Configuration** (identified gap from module README)
   - Allow different consent purposes to have different TTL/expiry settings.
   - Configuration stored per-purpose (e.g., `marketing: 365d`, `analytics: 90d`, `registry_check: 30d`).
   - Projection store includes per-purpose expiry metadata.
   - Expiry evaluation uses purpose-specific TTL when configured, falling back to global default.
   - Admin API to manage per-purpose expiry policies.

## 5. Acceptance Criteria

- Projection path is enabled via config and used by default when configured.
- `Require()` latency p95 < 5ms with projection hits.
- Event worker processes updates within 1s under normal load.
- Projection store falls back to canonical store on error without behavior change.
- Tests cover projection conflicts, fallback, and rebuild.

## 6. References

- PRD-002: Consent Management (TR-6)

---

## Revision History

| Version | Date       | Author       | Changes        |
| ------- | ---------- | ------------ | -------------- |
| 1.1     | 2025-12-27 | Engineering  | Added per-purpose expiry configuration (identified gap from README) |
| 1.0     | 2025-12-24 | Engineering  | Initial draft  |
