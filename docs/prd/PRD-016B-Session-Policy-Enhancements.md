# PRD-016B: Session Policy Enhancements

**Status:** Not Started  
**Priority:** P1 (Security/UX)  
**Owner:** Engineering  
**Dependencies:** PRD-016, PRD-022  
**Last Updated:** 2025-12-24

---

## 1. Purpose

Extend session management with configurable policies that were deferred from
PRD-016: sliding sessions, remember-me sessions, and concurrent session limits.

## 2. Scope

- Sliding session windows (extend expiry on activity).
- Remember-me sessions with longer TTL and explicit opt-in.
- Concurrent session limits with configurable eviction policy.
- Audit and metrics for policy enforcement.

## 3. Non-Scope

- MFA enrollment or step-up (PRD-021).
- Password recovery and change flows (PRD-022).
- Token format changes.

## 4. Functional Requirements

1. **Sliding Sessions**
   - Configurable window (e.g., 30m, 2h).
   - Activity on refresh extends session expiry within bounds.

2. **Remember-Me**
   - Opt-in flag on login.
   - Longer refresh/session TTLs with distinct audit events.

3. **Concurrent Session Limits**
   - Max active sessions per user (global default + per-tenant override).
   - Eviction policy: evict-oldest or deny-new (configurable).
   - Evictions emit audit events and metrics.

4. **Observability**
   - Metrics: active sessions, evictions, denies, sliding refreshes.

## 5. Acceptance Criteria

- Sliding sessions extend expiry only on valid activity and never exceed max TTL.
- Remember-me sessions persist longer and are visible in session listings.
- Concurrent session limits enforced on login/refresh across devices.
- Audit events emitted for evictions and denies.
- Tests cover sliding, remember-me, and limit enforcement.

## 6. References

- PRD-016: Token Lifecycle & Revocation
- PRD-022: Account Recovery & Credentials

---

## Revision History

| Version | Date       | Author      | Changes       |
| ------- | ---------- | ----------- | ------------- |
| 1.0     | 2025-12-24 | Engineering | Initial draft |
