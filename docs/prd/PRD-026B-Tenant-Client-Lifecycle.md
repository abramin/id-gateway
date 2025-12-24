# PRD-026B: Tenant & Client Lifecycle Management

**Status:** Complete
**Owner:** Engineering
**Last Updated:** 2025-12-24

---

## Purpose

PRD-026A defines tenant and client creation, retrieval, and update. This PRD extends the admin surface with **lifecycle management**: the ability to deactivate (and reactivate) tenants and clients.

Deactivation is required for:
- Compliance (disable clients for policy violations)
- Offboarding (gracefully sunset a tenant without data deletion)
- Incident response (immediately block compromised clients)

## Scope

- Add `TenantService.DeactivateTenant(ctx, tenantID)` and `ReactivateTenant(ctx, tenantID)`
- Add `TenantService.DeactivateClient(ctx, clientID)` and `ReactivateClient(ctx, clientID)`
- Expose via admin-only HTTP endpoints protected by `X-Admin-Token`
- Define behavior when deactivated entities are used in OAuth flows

## Non-Scope

- Hard deletion of tenants/clients (deferred; use deactivation for now)
- Cascading client deactivation when tenant is deactivated (clients remain active but tenant check blocks them)
- Bulk operations (single entity per call)
- Scheduled deactivation (no future-dated deactivation)

---

## Functional Requirements

### FR-1: Tenant Deactivation

**Endpoint:** `POST /admin/tenants/{id}/deactivate`

**Behavior:**
1. Load tenant by ID; return `404 not_found` if missing
2. If already inactive, return `409 conflict` with message "tenant is already inactive"
3. Set `status = inactive`
4. Emit audit event `tenant.deactivated`
5. Return `200 OK` with updated tenant details

**Effects:**
- All OAuth flows using clients under this tenant will fail at `ResolveClient` with `invalid_client`
- Existing tokens remain valid until expiry (no retroactive revocation)
- Clients under the tenant remain in their current status (not cascaded)

### FR-2: Tenant Reactivation

**Endpoint:** `POST /admin/tenants/{id}/reactivate`

**Behavior:**
1. Load tenant by ID; return `404 not_found` if missing
2. If already active, return `409 conflict` with message "tenant is already active"
3. Set `status = active`
4. Emit audit event `tenant.reactivated`
5. Return `200 OK` with updated tenant details

### FR-3: Client Deactivation

**Endpoint:** `POST /admin/clients/{id}/deactivate`

**Behavior:**
1. Load client by ID; return `404 not_found` if missing
2. If already inactive, return `409 conflict` with message "client is already inactive"
3. Set `status = inactive`
4. Emit audit event `client.deactivated`
5. Return `200 OK` with updated client details

**Effects:**
- OAuth flows using this client will fail at `ResolveClient` with `invalid_client`
- Existing tokens remain valid until expiry (no retroactive revocation)

### FR-4: Client Reactivation

**Endpoint:** `POST /admin/clients/{id}/reactivate`

**Behavior:**
1. Load client by ID; return `404 not_found` if missing
2. If already active, return `409 conflict` with message "client is already active"
3. Set `status = active`
4. Emit audit event `client.reactivated`
5. Return `200 OK` with updated client details

---

## Store Requirements

### TenantStore

```go
Update(ctx context.Context, tenant *Tenant) error
```

### ClientStore

Already has `Update` from PRD-026A.

---

## HTTP Responses

| Scenario | Status | Body |
|----------|--------|------|
| Success | `200 OK` | Updated entity JSON |
| Entity not found | `404 Not Found` | `{"error": "not_found", "message": "..."}` |
| Already in target state | `409 Conflict` | `{"error": "conflict", "message": "..."}` |
| Invalid UUID | `400 Bad Request` | `{"error": "bad_request", "message": "..."}` |
| Missing admin token | `401 Unauthorized` | `{"error": "unauthorized"}` |

---

## Audit Events

| Event | Fields |
|-------|--------|
| `tenant.deactivated` | `tenant_id`, `actor`, `request_id` |
| `tenant.reactivated` | `tenant_id`, `actor`, `request_id` |
| `client.deactivated` | `client_id`, `tenant_id`, `actor`, `request_id` |
| `client.reactivated` | `client_id`, `tenant_id`, `actor`, `request_id` |

---

## E2E Test Scenarios

```gherkin
@admin @tenant @lifecycle
Scenario: Deactivate tenant blocks OAuth flows
  Given I create a tenant with name "Lifecycle Test"
  And I create a client "Test App" under the tenant
  When I deactivate the tenant
  Then the response status should be 200
  When I initiate authorization with the client
  Then the response status should be 400
  And the response field "error" should equal "invalid_client"

@admin @tenant @lifecycle
Scenario: Deactivate already-inactive tenant returns conflict
  Given I create a tenant with name "Already Inactive"
  When I deactivate the tenant
  Then the response status should be 200
  When I deactivate the tenant
  Then the response status should be 409
  And the response field "error" should equal "conflict"

@admin @client @lifecycle
Scenario: Deactivate client blocks OAuth flows
  Given I create a tenant with name "Client Lifecycle"
  And I create a client "Deactivate Me" under the tenant
  When I deactivate the client
  Then the response status should be 200
  When I initiate authorization with the client
  Then the response status should be 400
  And the response field "error" should equal "invalid_client"

@admin @client @lifecycle
Scenario: Reactivate client restores OAuth flows
  Given I create a tenant with name "Restore Test"
  And I create a client "Restore Me" under the tenant
  And I deactivate the client
  When I reactivate the client
  Then the response status should be 200
  When I initiate authorization with the client
  Then the response status should be 201
```

---

## Implementation Notes

### Existing Domain Methods

The domain models already have `Deactivate()` methods that enforce the "already inactive" invariant:

```go
// internal/tenant/models/models.go
func (t *Tenant) Deactivate() error {
    if t.Status == TenantStatusInactive {
        return dErrors.New(dErrors.CodeInvariantViolation, "tenant is already inactive")
    }
    t.Status = TenantStatusInactive
    return nil
}
```

Service layer should call these methods and map `CodeInvariantViolation` to `409 Conflict`.

### Tenant-Scoped Client Operations

When tenant admin auth is implemented (per PRD-026A TODO), deactivate/reactivate should also support tenant-scoped variants:
- `DeactivateClientForTenant(ctx, tenantID, clientID)`
- `ReactivateClientForTenant(ctx, tenantID, clientID)`

---

## Features Identified During Implementation

The following features were implemented beyond original PRD scope:

1. **Tenant-Scoped Client Operations**: `DeactivateClientForTenant()`, `ReactivateClientForTenant()` ready for tenant admin auth
2. **Comprehensive E2E Test Coverage**: 12 Gherkin scenarios covering all lifecycle operations including edge cases
3. **ResolveClient Integration**: Status checks automatically block OAuth flows for inactive tenants/clients
4. **Metrics Integration**: Duration tracking on `ResolveClient()` for OAuth critical path observability

## Known Gaps

None - all requirements implemented including audit events, 409 conflict handling, and OAuth flow integration.

---

## Risks / Open Questions

1. **Token revocation on deactivation?** Current design leaves existing tokens valid. Should deactivation trigger bulk token revocation? (Deferred: adds complexity, can be added later)

2. **Cascade to clients?** When tenant is deactivated, should all clients auto-deactivate? (No: simpler to rely on tenant status check in `ResolveClient`)

3. **Reactivation window?** Should there be a mandatory waiting period before reactivation? (No: not needed for MVP)

---

## Future Improvements

### FI-1: Optimistic Locking for Concurrent Updates

**Priority:** Medium (required before database backend or multi-instance deployment)

**Problem:** The current read-modify-write pattern in deactivation/reactivation is vulnerable to lost updates when concurrent requests modify the same entity.

**Risks:**
- Concurrent `UpdateClient` + `Deactivate` can silently lose the deactivation
- Concurrent `RotateSecret` + `Deactivate` can overwrite the new secret hash
- TOCTOU: validation occurs against stale in-memory state

**Mitigation (current):** In-memory store mutex provides basic protection within a single process.

**Recommended fix:** Add `Version int64` field to Client and Tenant models with optimistic locking semantics:
1. Store checks `WHERE version = expected` on update
2. Returns `ErrConcurrentModification` on mismatch
3. Service retries with exponential backoff (max 3 attempts)

**Scope:** ~100 lines across model, store, and service layers.

---

## Revision History

| Version | Date       | Author      | Changes                                                                   |
| ------- | ---------- | ----------- | ------------------------------------------------------------------------- |
| 1.0     | 2025-12-23 | Engineering | Initial draft; lifecycle management carved out from PRD-026A              |
| 1.1     | 2025-12-24 | Engineering | Added FI-1: Optimistic locking for concurrent updates                     |
| 1.2     | 2025-12-24 | Engineering | Status verification: all requirements complete                            |
|         |            |             | - Updated status to Complete                                              |
|         |            |             | - Added Features Identified During Implementation section                 |
|         |            |             | - Confirmed E2E test coverage (12 scenarios)                              |
