# PRD-002C: Admin Consent Management

**Status:** Draft
**Priority:** P2
**Owner:** Engineering Team
**Dependencies:** PRD-002 (Consent Management)
**Last Updated:** 2025-12-28

---

## 1. Overview

### Problem Statement

The current consent management system provides user-facing endpoints for grant, revoke, and delete operations. However, admin operations are limited to a single bulk revoke-all endpoint. Real-world operations require:

1. **Support workflows**: Admins need to view a user's consents to troubleshoot issues
2. **Selective admin revocation**: Admins may need to revoke specific purposes (e.g., disable registry access for a user without revoking login consent)
3. **Legal request handling**: GDPR erasure requests often come through legal/support channels, requiring admin-initiated deletion
4. **User self-service delete concerns**: Allowing users to permanently delete their own consent records may be too destructive for some deployments

### Goals

- Add admin endpoints for viewing, selectively revoking, and deleting user consents
- Evaluate whether admin-only delete is safer than user self-service delete
- Add user-facing revoke-all endpoint for "pause all" functionality
- Maintain audit attribution for all admin actions

### Non-Goals

- Consent delegation (admin granting consent on behalf of user)
- Consent templates or bulk operations across multiple users
- Admin UI (API-only)

---

## 2. User Stories

**As a** support agent
**I want to** view a user's consent records
**So that** I can diagnose why their operations are failing

**As a** support agent
**I want to** revoke specific consents for a user
**So that** I can disable problematic functionality without affecting other services

**As a** compliance officer
**I want to** delete all consent records for a user upon legal request
**So that** I can fulfill GDPR erasure obligations

**As a** user
**I want to** revoke all my consents at once
**So that** I can "pause" all data processing without losing my audit trail

---

## 3. Functional Requirements

### FR-1: Admin List User Consents

**Endpoint:** `GET /admin/consent/users/{user_id}`

**Description:** View all consent records for a specific user. Essential for support workflows.

**Input:**

- Path: `user_id` (required)
- Query: `status` (optional) - "active", "expired", "revoked"
- Query: `purpose` (optional) - filter by purpose
- Header: `X-Admin-Token` (required)

**Output (Success - 200):**

```json
{
  "user_id": "user_123",
  "consents": [
    {
      "id": "consent_abc123",
      "purpose": "login",
      "granted_at": "2025-12-03T10:00:00Z",
      "expires_at": "2026-12-03T10:00:00Z",
      "revoked_at": null,
      "status": "active"
    }
  ]
}
```

**Authorization:**

- Requires valid `X-Admin-Token` header
- Admin token validated via admin middleware

**Error Cases:**

- 401 Unauthorized: Missing or invalid admin token
- 404 Not Found: User does not exist
- 500 Internal Server Error: Store failure

**Audit Event:**

```json
{
  "action": "consent_viewed",
  "user_id": "user_123",
  "actor_id": "admin_token_id",
  "reason": "admin_support"
}
```

---

### FR-2: Admin Revoke Specific Consents

**Endpoint:** `POST /admin/consent/users/{user_id}/revoke`

**Description:** Revoke specific purposes for a user. More granular than revoke-all.

**Input:**

```json
{
  "purposes": ["registry_check", "vc_issuance"],
  "reason": "security_concern"
}
```

**Output (Success - 200):**

```json
{
  "revoked": [
    {
      "purpose": "registry_check",
      "revoked_at": "2025-12-28T12:00:00Z",
      "status": "revoked"
    }
  ],
  "message": "Consent revoked for 1 purpose"
}
```

**Authorization:**

- Requires valid `X-Admin-Token` header

**Business Logic:**

1. Validate admin token
2. Validate user exists
3. Validate purposes are valid enum values
4. For each purpose:
   - Find active consent for user+purpose
   - If found and active, set RevokedAt = now
   - Skip if not found, expired, or already revoked (idempotent)
5. Emit audit event with admin actor ID and reason
6. Return list of revoked consents

**Error Cases:**

- 400 Bad Request: Empty purposes array or invalid purpose
- 401 Unauthorized: Missing or invalid admin token
- 404 Not Found: User does not exist
- 500 Internal Server Error: Store failure

**Audit Event:**

```json
{
  "action": "consent_revoked",
  "user_id": "user_123",
  "purpose": "registry_check",
  "actor_id": "admin_token_id",
  "reason": "security_concern",
  "decision": "revoked"
}
```

---

### FR-3: Admin Delete All Consents (GDPR)

**Endpoint:** `DELETE /admin/consent/users/{user_id}`

**Description:** Permanently delete all consent records for a user. Used for GDPR Article 17 requests received through legal channels.

**Input:**

- Path: `user_id` (required)
- Header: `X-Admin-Token` (required)
- Body (optional):

```json
{
  "reason": "gdpr_erasure_request",
  "reference": "LEGAL-2025-1234"
}
```

**Output (Success - 200):**

```json
{
  "message": "All consents deleted for user user_123",
  "reference": "LEGAL-2025-1234"
}
```

**Authorization:**

- Requires valid `X-Admin-Token` header

**Business Logic:**

1. Validate admin token
2. Validate user exists (optional - may delete even if user record gone)
3. Delete all consent records for user from store
4. Emit audit event with admin actor ID and reference
5. Return confirmation

**Error Cases:**

- 401 Unauthorized: Missing or invalid admin token
- 500 Internal Server Error: Store failure

**Audit Event:**

```json
{
  "action": "consent_deleted",
  "user_id": "user_123",
  "actor_id": "admin_token_id",
  "reason": "gdpr_erasure_request",
  "reference": "LEGAL-2025-1234",
  "decision": "deleted"
}
```

---

### FR-4: User Revoke All Consents

**Endpoint:** `POST /auth/consent/revoke-all`

**Description:** Revoke all active consents for the authenticated user. Unlike delete, this preserves the audit trail and allows re-granting.

**Input:**

- Header: `Authorization: Bearer <token>`
- No request body required

**Output (Success - 200):**

```json
{
  "revoked_count": 3,
  "message": "All consents revoked"
}
```

**Note:** This endpoint already exists per PRD-002 FR-2.1, but documenting here for completeness.

---

## 4. Design Decision: User Delete vs Admin-Only Delete

### Current State

- `DELETE /auth/consent` - User can delete their own consents (GDPR self-service)
- `POST /admin/consent/users/{user_id}/revoke-all` - Admin can revoke all

### Options

| Approach | Pros | Cons |
|----------|------|------|
| **Keep both** (user + admin delete) | Maximum user control, GDPR self-service | Risk of accidental permanent deletion |
| **Admin-only delete** | Controlled, auditable, prevents accidents | Requires support ticket for erasure |
| **User delete with confirmation** | Balance of control and safety | More complex UX |

### Recommendation: Keep Both, but Differentiate

1. **User-facing delete** (`DELETE /auth/consent`):
   - Keep for GDPR self-service
   - Consider adding confirmation requirement in future (e.g., `?confirm=true`)
   - Rate limit aggressively (ClassSensitive)

2. **Admin delete** (`DELETE /admin/consent/users/{user_id}`):
   - Primary path for legal requests
   - Includes reference field for tracking
   - Richer audit attribution

The admin endpoint doesn't replace the user endpoint - they serve different workflows:
- User delete: Self-service GDPR exercise
- Admin delete: Legal/compliance team handling formal requests

---

## 5. API Specifications

### Endpoint Summary

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `GET /admin/consent/users/{user_id}` | GET | Admin | View user consents |
| `POST /admin/consent/users/{user_id}/revoke` | POST | Admin | Revoke specific purposes |
| `DELETE /admin/consent/users/{user_id}` | DELETE | Admin | Delete all (GDPR) |
| `POST /auth/consent/revoke-all` | POST | User | Revoke all (existing) |
| `DELETE /auth/consent` | DELETE | User | Delete all (existing) |

---

## 6. Security Requirements

### SR-1: Admin Authorization

- All admin endpoints require valid `X-Admin-Token`
- Admin token must be validated against configured admin secret
- Failed admin auth attempts must be logged

### SR-2: Audit Attribution

- All admin actions must include `actor_id` in audit events
- Admin token identifier (not secret) used as actor_id
- Reason field required for revoke/delete operations

### SR-3: Rate Limiting

- Admin endpoints use ClassWrite rate limits
- User delete uses ClassSensitive rate limits

---

## 7. Observability Requirements

### Metrics

- `admin_consent_views_total` - Counter of admin list operations
- `admin_consent_revokes_total{purpose}` - Counter by purpose
- `admin_consent_deletes_total` - Counter of admin deletions
- `consent_delete_self_service_total` - Counter of user self-deletions

### Logging

- Admin operations logged at INFO level
- Include user_id, actor_id, and operation

---

## 8. Testing Requirements

### E2E Tests (Gherkin)

- [ ] Admin can view user consents
- [ ] Admin can revoke specific purposes for user
- [ ] Admin can delete all consents for user
- [ ] Admin actions include actor_id in audit
- [ ] Admin revoke is idempotent
- [ ] User revoke-all preserves records (vs delete removes them)

### Integration Tests

- [ ] Admin token validation for all admin endpoints
- [ ] 404 when user doesn't exist (for view/revoke)
- [ ] Audit events include reference field for legal tracking

---

## 9. Acceptance Criteria

- [ ] Admins can view any user's consent records
- [ ] Admins can selectively revoke specific purposes
- [ ] Admins can delete all consents with legal reference tracking
- [ ] All admin actions attributed in audit log
- [ ] User self-service delete remains available
- [ ] User revoke-all provides "pause" functionality

---

## 10. Open Questions

1. **Should admin delete require a reason/reference?** (Currently optional)
2. **Should we add a confirmation requirement to user delete?** (e.g., `?confirm=true`)
3. **Should admin revoke support a cooldown bypass?** (Currently uses same 5-min cooldown)

---

## 11. Future Enhancements

- Admin bulk operations (revoke/delete across multiple users)
- Admin consent grant on behalf of user (requires legal review)
- Audit log search by reference number
- Soft-delete with retention period before hard delete

---

## Revision History

| Date | Version | Notes | Author |
|------|---------|-------|--------|
| 2025-12-28 | v0.1 | Initial draft | Engineering |
