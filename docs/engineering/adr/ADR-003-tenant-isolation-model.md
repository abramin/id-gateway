# ADR-003: Tenant Isolation Model

- **Status:** Accepted
- **Date:** 2026-01-01
- **Owners:** Platform & Security

## Context
- The platform serves multiple tenants with separate client registrations, policies, and audit boundaries. Staff review called out the lack of an explicit isolation model.
- Architecture favors clean service boundaries and typed identifiers, but current storage and middleware do not consistently scope by tenant or enforce issuer/audience binding to a tenant.
- Regulatory features (regulated mode, consent minimization, per-tenant audit exports) require deterministic isolation to prevent cross-tenant data exposure.

## Decision
- Adopt **logical isolation with strict tenant scoping** across all layers:
  - Every domain model and request context carries a typed `TenantID`; repositories require it as a parameter, and queries must include explicit tenant predicates.
  - Authentication and token issuance bind `iss` and `aud` to the tenant’s namespace (`https://{tenant}.credo/idp`), and middleware rejects tokens whose issuer or client does not match the resolved tenant context.
  - Per-tenant configuration (keys, policies, rate limits, redirect URIs, consent templates) is stored in Postgres tables keyed by `TenantID` with unique constraints to prevent cross-tenant reuse.
- **Transport isolation:** admin and operational APIs require a tenant header or path segment; public OAuth endpoints resolve tenant via client metadata, not caller-supplied headers, to avoid spoofing.
- **Data plane isolation:** caches (Redis) prefix keys with `TenantID`; background workers process jobs partitioned by tenant to avoid mixing events and to enable tenant-level throttling or pausing.
- **Observability and auditing:** logs, metrics, and audit events include `tenant_id` dimensions; cross-tenant aggregation is limited to anonymous, privacy-safe metrics in regulated mode.

## Consequences
- Requires refactoring repository interfaces and middleware to accept typed tenant identifiers, adding validation to guard against missing/unknown tenants before performing business logic.
- Tenant-aware JWKS exposure and token validation must align with the signing ADR to ensure keys and issuers are segregated per tenant.
- Operationally, incident response and backups/restores run at tenant granularity; data exports and deletion flows must respect tenant partitions.
