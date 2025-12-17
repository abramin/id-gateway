# PRD-001B: Admin-Only User & Session Deletion

**Status:** Complete  
**Owner:** Engineering  
**Last Updated:** 2025-12-11

---

## Purpose
GDPR/CCPA erasure requires the auth service to delete a user and all of their active sessions on demand. This PRD defines a minimal, admin-only control plane (API or CLI) that is isolated from the public auth flow in PRD-001.

## Scope
- Add `AuthService.DeleteUser(ctx, userID)` orchestration (deletes sessions first, then user; emits audit events).
- Expose the capability via an admin-only HTTP endpoint (`DELETE /admin/auth/users/{user_id}`) protected by an admin token, or an equivalent CLI hook that calls the same service method.
- Keep public OAuth/OIDC routes unchanged; no public/self-service delete.

## Non-Scope
- No soft-delete or retention policies (demo-only hard delete).
- No bulk deletes; single user per call.
- No upstream data scrub (e.g., audit store retention) beyond emitting events.

## Functional Requirements
1. **Service orchestration**
   - `DeleteUser(ctx, userID)` MUST:
     1. Load the user; return `not_found` if missing.
     2. Delete all sessions for that user (`SessionStore.DeleteSessionsByUser`), tolerating `not_found`.
     3. Delete the user (`UserStore.Delete`).
     4. Emit audit events: `sessions_revoked` (after session delete) and `user_deleted` (after user delete) with `user_id` (and email if available).
   - Order is fixed: sessions first, then user.

2. **Stores** (moved from PRD-001)
   - `UserStore` MUST implement `Delete(ctx, id uuid.UUID)`.
   - `SessionStore` MUST implement `DeleteSessionsByUser(ctx, userID uuid.UUID)`.

3. **Admin-only transport**
   - HTTP: `DELETE /admin/auth/users/{user_id}`
     - Guarded by an admin token header `X-Admin-Token` matched against `ADMIN_API_TOKEN` configuration.
     - Returns `204 No Content` on success, `404 not_found` if the user is missing, `400` for invalid UUID, standard `5xx/4xx` for other errors.
   - CLI (optional alternate surface): invoke `DeleteUser` with the same semantics and audit emission; must not bypass service orchestration.

4. **Separation from public auth API**
   - Admin route lives under `/admin/auth/*` and is NOT registered alongside `/auth/authorize|token|userinfo` unless the admin middleware is applied.
   - Requires explicit admin credential (token) independent of OAuth client credentials or user tokens.

## Configuration
- `ADMIN_API_TOKEN`: secret required by admin HTTP middleware. For demo environments, a default token MAY be provided; production must set a strong secret.

## Audit
- Emit `sessions_revoked` when bulk-deleting sessions by user.
- Emit `user_deleted` after successful user deletion.
- Include `user_id`, `subject`, and contextual fields (e.g., email when known, request_id when present).

## Risks / Open Questions
- Should admin tokens rotate automatically? (Out of scope; manual rotation acceptable for now.)
- Should deletion also purge audit logs in regulated deployments? (Deferred to PRD-006.)

## Revision History
- 1.0 (2025-12-11): Initial draft; carved out delete flows from PRD-001 and defined admin surface.
