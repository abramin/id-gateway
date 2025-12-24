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
- Session/consent/allowlist entries require expiry (or explicit "no-expiry" flag) and issuer metadata; constructors reject missing expiry context.
- **Future:** When static admin token is used, comparison should use `crypto/subtle.ConstantTimeCompare` to prevent timing attacks.

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

### SR-10 Consent/Data Rights Persistence (from completed PRDs)

- SQL posture: RLS enabled for tenant/user scoping and partial indexes on `(user_id, purpose, status)`; projections/read models carry documented `EXPLAIN` plans.
- Event logs are append-only with hash chaining; projections rebuild from events and fail closed on missing schema/config.
- GDPR redaction: PII fields are nulled/removed within SLA; rebuild paths enforce redaction and are audited.

### SR-11 Authorization Infrastructure

Structural enforcement of authorization rules that cannot be bypassed by handler or service misuse.

#### A. Tenant-Scoped Repositories

Repository interfaces require tenant context before any operation, making cross-tenant queries structurally impossible:

```go
// Structural safety - can't query without tenant context
type ConsentStore interface {
    ForTenant(tid domain.TenantID) TenantScopedConsentStore
}

type TenantScopedConsentStore interface {
    GetConsent(ctx context.Context, id domain.ConsentID) (*Consent, error)
    ListByUser(ctx context.Context, uid domain.UserID) ([]*Consent, error)
}

// Usage: store.ForTenant(tid).GetConsent(cid)
// Impossible to call without tenant context
```

#### B. Central Authorizer API

Single enforcement point for cross-cutting authorization rules. Services delegate authorization checks rather than implementing inline:

```go
// Single enforcement point for cross-cutting authorization rules
type Authorizer interface {
    CanReadConsent(ctx context.Context, actor Actor, consent *Consent) (bool, error)
    CanRevokeConsent(ctx context.Context, actor Actor, consent *Consent) (bool, error)
    CanDeleteUser(ctx context.Context, actor Actor, user *User) (bool, error)
}

// Actor carries identity + capabilities from validated token
type Actor struct {
    UserID     domain.UserID
    TenantID   domain.TenantID
    Roles      []string
    Scopes     []string
}
```

#### C. Typed Domain IDs

Compile-time type safety prevents ID mix-ups (passing UserID where TenantID expected). Parse functions validate at trust boundaries:

```go
type UserID    uuid.UUID  // Distinct type, not alias
type TenantID  uuid.UUID  // Cannot accidentally pass UserID here

// Parse at trust boundaries - rejects empty, nil, malformed
func ParseUserID(s string) (UserID, error)
func ParseTenantID(s string) (TenantID, error)
```

#### D. Invariant Tests

Security invariants encoded as tests that document "never again" bugs:

- Cross-type ID assignment must fail at compile time
- Attack vectors (SQL injection, path traversal) must be rejected by parsing
- Cross-tenant access must be denied
- All ID types must have consistent validation behavior

#### E. Fuzz Tests

Trust boundary functions (ID parsing, request decoding) must be fuzz tested to verify:

- No panics on arbitrary input
- Valid IDs round-trip correctly
- Non-UTF8 input is rejected

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
- [ ] Consent/data rights persistence uses RLS + partial indexes with EXPLAIN evidence; append-only event log with hash chaining and GDPR redaction enforced.
- [ ] Tenant-scoped repository interfaces require TenantID before any operation.
- [ ] Central Authorizer enforces cross-cutting rules (admin scope, tenant boundary).
- [ ] Actor context extracted from validated tokens, never from request headers directly.
- [ ] Authorization failures return typed results, not errors.
- [ ] Typed domain IDs prevent cross-type assignment at compile time.
- [ ] Security invariant tests cover attack vectors and cross-tenant access.
- [ ] Fuzz tests verify no panics on arbitrary input to trust boundary functions.

---

## 5. Revision History

| Version | Date       | Author       | Changes                                                           |
| ------- | ---------- | ------------ | ----------------------------------------------------------------- |
| 1.2     | 2025-12-21 | Engineering  | Added SR-11 Authorization Infrastructure (tenant-scoped repos, central authorizer, typed IDs, invariant/fuzz tests) |
| 1.1     | 2025-12-18 | Security Eng | Added validation order, immutability, sensitive data, result handling |
| 1.0     | 2025-12-18 | Security Eng | Initial security addendum                                         |
