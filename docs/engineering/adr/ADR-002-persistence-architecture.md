# ADR-002: Persistence Architecture (Postgres + Redis)

- **Status:** Accepted
- **Date:** 2026-01-01
- **Owners:** Platform & Data

## Context
- The current architecture uses PostgreSQL as the canonical data store and Redis for hot-path state (sessions, token revocation list, registry cache). In-memory stores are test-only.
- Kafka-backed audit streaming uses an outbox pipeline sourced from Postgres.
- We need durable storage with predictable consistency and a low-latency cache, while keeping service boundaries clear and avoiding partial writes.

## Decision
- **PostgreSQL is the system of record** for tenants, users, sessions, refresh tokens, consent grants, audit events, and decision artifacts. All writes run inside service-level transactions; outbox entries are persisted alongside domain writes.
- **Redis is the hot cache** for sessions, the token revocation list (TRL), and registry cache lookups. Redis data is treated as ephemeral and derivable from Postgres; when Redis is not configured, services fall back to Postgres.
- **Rate limiting** uses PostgreSQL-backed sliding windows today; a Redis backend is planned (PRD-017B).
- Persistence adapters follow ports-and-adapters: domain services depend on interfaces; Postgres and Redis adapters implement those contracts; in-memory adapters remain test-only. Migrations are managed via `migrations/`.
- Data access enforces **tenant scoping** at the repository layer using typed `TenantID` parameters, and multi-tenant queries must include explicit tenant predicates.

## Consequences
- Maintain Redis adapters for sessions, TRL, and registry cache, including health checks and Postgres fallback behavior.
- Add observability for Postgres/Redis latency, error rates, replication lag, and cache hit ratios; monitor Redis unavailability and TRL lookup failures.
- Plan Redis-backed rate limiting as a follow-on improvement once PRD-017B is scheduled.
