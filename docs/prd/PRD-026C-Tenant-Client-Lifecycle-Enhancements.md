# PRD-026C: Tenant & Client Lifecycle Enhancements

**Status:** Not Started  
**Priority:** P1 (Hardening)  
**Owner:** Engineering  
**Dependencies:** PRD-026B, PRD-016, PRD-026  
**Last Updated:** 2025-12-24

---

## 1. Purpose

Extend tenant/client lifecycle controls beyond basic deactivate/reactivate to
cover deletion, scheduling, and concurrency safety.

## 2. Scope

- Hard deletion of tenants and clients with safeguards.
- Scheduled deactivation/reactivation windows.
- Optional token revocation on deactivation.
- Optimistic locking for concurrent updates.
- Tenant-scoped lifecycle operations for tenant admins.

## 3. Non-Scope

- UI design and RBAC implementation (PRD-026).
- Audit log deletion (PRD-006).

## 4. Functional Requirements

1. **Hard Delete**
   - Admin-only delete with explicit confirmation.
   - Audit events and retention guards.

2. **Scheduled Lifecycle**
   - Schedule deactivate/reactivate timestamps.
   - Background worker executes schedules reliably.

3. **Token Revocation on Deactivation**
   - Optional flag to revoke all tokens for affected tenant/client.
   - Integrates with PRD-016 revocation lists.

4. **Optimistic Locking**
   - `Version` field on Tenant/Client.
   - Store rejects stale updates with explicit error.

5. **Tenant-Scoped Operations**
   - `DeactivateClientForTenant` and `ReactivateClientForTenant` enforced.

## 5. Acceptance Criteria

- Hard deletion is audit-logged and guarded.
- Scheduled lifecycle jobs execute on time and are idempotent.
- Optional token revocation is enforced for deactivated tenants/clients.
- Concurrent updates return conflict without data loss.
- Tenant-scoped operations cannot cross tenant boundaries.

## 6. References

- PRD-026B: Tenant & Client Lifecycle Management
- PRD-016: Token Lifecycle & Revocation

---

## Revision History

| Version | Date       | Author      | Changes       |
| ------- | ---------- | ----------- | ------------- |
| 1.0     | 2025-12-24 | Engineering | Initial draft |
