# ADR-002: Persistence Architecture (Postgres + Redis)

- **Status:** Accepted
- **Date:** 2026-01-01
- **Owners:** Platform & Data

## Context
- Core session, consent, revocation, and audit state is currently backed by in-memory stores, which are not durable and diverge between instances. Staff review highlighted this as a production blocker.
- The platform already uses Postgres for other components and Redis for rate limiting in design discussions, and the architecture favors clear service boundaries with ports/adapters.
- We need a durable system of record with predictable consistency semantics, plus a low-latency cache for revocation and rate limiting, while avoiding partial writes across services.

## Decision
- **Postgres is the system of record** for tenants, users, sessions, refresh tokens, consent grants, audit events, and decision artifacts. All writes run inside transactions with explicit isolation levels per service (read committed by default; serializable where cross-table invariants are enforced).
- **Redis is the authoritative cache** for short-lived cross-instance state: token revocation list entries, rate-limit counters, nonce/state/PKCE verifiers, and session locks. Redis data is treated as ephemeral but must be derivable from Postgres, and operations default to fail-closed for security-sensitive flows (revocation, nonce reuse checks).
- Persistence adapters follow the existing ports-and-adapters pattern: domain services depend on interfaces; Postgres and Redis adapters implement those contracts and support dependency injection for tests. Migrations are managed via existing `migrations/` tooling with repeatable migration steps.
- Outbox + worker pattern remains the durability mechanism for audit pipelines: writes to Postgres outbox tables and Redis caches occur in a single transaction per service boundary; workers publish asynchronously with retry/backoff and observability around backlog depth.
- Data access enforces **tenant scoping** at the repository layer using typed `TenantID` parameters, and multi-tenant queries must include explicit tenant predicates to prevent cross-tenant leaks.

## Consequences
- Implement Postgres-backed stores for auth, consent, revocation, and audit components, and dual-write during migration to maintain compatibility with in-memory adapters until cutover completion.
- Introduce Redis-backed revocation and rate-limit adapters with TTL policies aligned to token lifetimes; add health checks and circuit-breaker behavior when Redis is unavailable.
- Extend observability: metrics for Postgres/Redis latency, error rates, replication lag, and cache hit ratios; alerts for revocation cache misses and Redis unavailability that would force stricter fail-closed paths.
