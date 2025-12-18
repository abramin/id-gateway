# PRD-028: Security Enhancements for Completed Core Modules

**Status:** Not Started  
**Priority:** P0 (Security)  
**Owner:** Security Engineering  
**Depends on:** PRD-001, PRD-001B, PRD-002, PRD-016, PRD-026A  
**Last Updated:** 2025-12-18

---

## 1. Purpose

Aggregate secure-by-design requirements for already completed PRDs without altering their baselines. This PRD binds Auth, Admin User Deletion, Consent, Token Lifecycle/Revocation, and Tenant/Client Management to structural security guarantees.

---

## 2. Scope

- Auth & Sessions (PRD-001)
- Admin User Deletion (PRD-001B)
- Consent Management (PRD-002)
- Token Lifecycle & Revocation (PRD-016)
- Tenant/Client Management (PRD-026A)

---

## 3. Security Requirements

### SR-1 Invalid States Unrepresentable

- Introduce typed enums for session/token status and consent purpose/status; constructors enforce issuer/audience, expiry, client binding, and tenant scoping.
- Allowlist/consent commands must be constructed via value objects; raw maps/partial structs are forbidden at service boundaries.

### SR-2 Trust Boundaries Explicit

- Handlers accept only validated command DTOs; service interfaces take value objects, not raw HTTP payloads.
- Admin operations require a boundary component returning a scoped admin principal (role, tenant, expiry); handlers cannot read headers directly.

### SR-3 Deny by Default

- Missing consent/evidence ⇒ explicit denial from services (no implicit allow).
- Missing/invalid config for rate limits, token signing keys, or tenant/client metadata ⇒ fail-fast with operational alert.

### SR-4 Least Privilege (Structural)

- Split ports per responsibility: `SessionReader` vs `SessionMutator`, `ConsentAppender` vs `ConsentReader`, `TokenRevoker` vs `TokenIssuer`.
- Tenant and client repositories enforce tenant scoping in interfaces (require TenantID value object on every operation).

### SR-5 Secrets & Authority Are Short-Lived/Revocable

- Admin authentication uses short-lived, signed admin session tokens with revocation list; static `ADMIN_API_TOKEN` only allowed in demo mode.
- Token signing/verification keys carry version IDs; rotation cadence and rollback drills are required. Refresh/revoke checks consult centralized revocation lists.
- Session/consent/allowlist entries require expiry (or explicit “no-expiry” flag) and issuer metadata; constructors reject missing expiry context.

### SR-6 Auditability

- All privileged/admin actions emit `admin.action` audit events with actor, scope, decision, and correlation ID. Emission is non-blocking with outbox fallback.

### SR-7 Validation & Immutability

- Validation order enforced (Origin → Size → Lexical → Syntax → Semantics) in command DTOs used by handlers; raw maps are rejected at boundaries.
- Identity-bearing fields (IDs, tenant/client bindings, issued-at/expiry) are immutable and exposed via getters; state transitions go through validated methods/builders.
- Constructors/builders remove setters and enforce consistency before returning entities/value objects.

### SR-8 Sensitive Data Handling

- Secrets (admin tokens, signing keys) modeled as read-once wrappers with zeroization after use; error/log mappers must not echo user input or secrets.
- Audit/log redaction lists are explicit; user-provided fields are redacted unless whitelisted.

### SR-9 Result-Oriented Failures

- Expected denial paths (auth failure, consent missing, rate limit exceeded) return typed result objects, not generic errors or string parsing.
- Service interfaces use result types for allow/deny so callers cannot accidentally treat errors as allow.

---

## 4. Acceptance Criteria

- [ ] Enums and constructors added for session/token/consent state; raw struct literals rejected in services.
- [ ] Admin principal boundary implemented; handlers refactored to consume principals only.
- [ ] Services deny requests lacking consent/evidence/config, with audit + alert.
- [ ] Ports split for least privilege; tenant/client operations require TenantID in signatures.
- [ ] Admin auth uses expiring tokens + revocation; key rotation/versioning documented and enforced in code.
- [ ] Audit events emitted for all admin/privileged actions with correlation IDs.
- [ ] Validation order documented and enforced in command DTOs; malformed inputs rejected before semantics.
- [ ] Entities expose immutable identity fields; state transitions use validated methods/builders.
- [ ] Secrets handled via read-once wrappers; user input is not echoed in errors/logs.
- [ ] Result types cover expected deny paths; no reliance on stringly-typed errors.

---

## 5. Revision History

| Version | Date       | Author       | Changes                                                           |
| ------- | ---------- | ------------ | ----------------------------------------------------------------- |
| 1.1     | 2025-12-18 | Security Eng | Added validation order, immutability, sensitive data, result handling |
| 1.0     | 2025-12-18 | Security Eng | Initial security addendum                                         |
