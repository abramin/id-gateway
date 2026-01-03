# ADR-003: Tenant Isolation Model

- **Status:** Accepted
- **Date:** 2026-01-01
- **Owners:** Platform & Security

## Context
- The platform serves multiple tenants with separate client registrations and lifecycle controls. The architecture now includes a dedicated tenant service (PRD-026A/026B).
- Services share infrastructure (Postgres + Redis), so tenant isolation must be enforced consistently at the application and data layers.
- OAuth flows must respect tenant and client lifecycle states (deactivate/reactivate) to prevent cross-tenant access.

## Decision
- Adopt **logical isolation with strict tenant scoping**:
  - Domain models use typed `TenantID` values; repositories require tenant-scoped queries with explicit tenant predicates.
  - Tenants and clients are stored in Postgres and managed by the tenant service; lifecycle transitions are explicit (`DeactivateTenant`, `ReactivateTenant`, `DeactivateClient`, `ReactivateClient`).
  - Auth flows resolve tenant and client via `ResolveClient` and enforce `tenant.IsActive()` and `client.IsActive()` as the OAuth choke point.
- **Transport isolation:** admin endpoints manage tenants and clients via `/admin/tenants/{tenant_id}` routes; OAuth flows rely on client registration rather than caller-supplied tenant headers.

## Consequences
- Stores and services must keep tenant predicates explicit and fail fast on unknown tenants or inactive tenant/client states.
- Admin handlers must enforce tenant lifecycle controls consistently across tenant and client management endpoints.
- Data exports and deletion flows must operate within tenant boundaries and use tenant-scoped identifiers end-to-end.
