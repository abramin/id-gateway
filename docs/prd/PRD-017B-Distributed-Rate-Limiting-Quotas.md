# PRD-017B: Distributed Rate Limiting & Quotas

**Status:** Not Started  
**Priority:** P0 (Operational)  
**Owner:** Engineering  
**Dependencies:** PRD-017, PRD-020  
**Last Updated:** 2025-12-27

---

## 1. Purpose

Scale rate limiting to multi-instance deployments by introducing distributed
stores and deferred quota APIs from PRD-017.

## 2. Scope

- Redis-backed distributed rate limiter (Lua scripts).
- Postgres-backed limiter (TR-6 indexing patterns).
- Quota API endpoints (FR-5) for partner billing/usage.
- 3-state circuit breaker with half-open state.
- IETF RateLimit header draft compliance (identified gap from module README).

## 3. Non-Scope

- Adaptive limits, ML detection, or CAPTCHA challenges (PRD-017C).
- UI dashboards (PRD-026).

## 4. Functional Requirements

1. **Distributed Store**
   - Redis primary, Postgres optional fallback.
   - Consistent limits across instances with bounded retries.

2. **Circuit Breaker**
   - Closed → Open → Half-Open transitions with backoff.
   - Metrics for state transitions and error rates.

3. **Quota APIs**
   - HTTP endpoints to read/update quotas.
   - Audit events for admin changes.

4. **IETF RateLimit Header Compliance** (draft-ietf-httpapi-ratelimit-headers)
   - Migrate from `X-RateLimit-*` headers to IETF standard `RateLimit-*` headers.
   - Support `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset` headers.
   - Include `RateLimit-Policy` header for communicating quota policies.
   - Maintain backward compatibility with `X-RateLimit-*` headers during transition period (configurable).
   - Reference: https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/

## 5. Acceptance Criteria

- Rate limiting is consistent across multiple instances.
- Half-open state safely probes downstream store health.
- Quota API endpoints enforce auth and validation.
- Metrics cover store latency, breaker state, and quota changes.

## 6. References

- PRD-017: Rate Limiting & Abuse Prevention
- PRD-020: Operational Readiness & SRE

---

## Revision History

| Version | Date       | Author      | Changes       |
| ------- | ---------- | ----------- | ------------- |
| 1.1     | 2025-12-27 | Engineering | Added IETF RateLimit header compliance (identified gap from README) |
| 1.0     | 2025-12-24 | Engineering | Initial draft |
