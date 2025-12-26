# Auth Module

This document describes the Domain-Driven Design (DDD) approach applied to the `internal/auth` bounded context in Credo.

---

## Bounded Context Definition

**Context:** `internal/auth`

**Purpose:** Implement the gateway's authentication flows and security lifecycle:

- Authorization requests produce authorization codes and sessions
- Token requests exchange codes/refresh tokens for JWTs
- Sessions and tokens can be revoked
- Userinfo is served for authenticated sessions
- Audit/security telemetry is emitted for key transitions

This is a distinct bounded context because its language and invariants are specific: codes, sessions, refresh tokens, consent and revocation are not generic "user management" concerns.

---

## Ubiquitous Language

| Domain Term              | Code Location                                  |
| ------------------------ | ---------------------------------------------- |
| **User**                 | `models.User`                                  |
| **Session**              | `models.Session`                               |
| **Authorization Code**   | `models.AuthorizationCodeRecord`               |
| **Refresh Token**        | `models.RefreshTokenRecord`                    |
| **Authorize**            | `service/authorize.go`                         |
| **Token exchange**       | `service/token_exchange.go`                    |
| **Token refresh**        | `service/token_refresh.go`                     |
| **Revocation**           | `service/token_revocation.go`, `service/session_revoke.go` |
| **UserInfo**             | `service/userinfo.go`                          |
| **Device Binding**       | `device/device.go`, `service/device_binding.go` |
| **Audit events**         | emitted via `service/service.go#logAudit`      |

---

## Module Structure

```
internal/auth/
├── adapters/           # External service adapters (e.g., ratelimit)
├── device/             # Device binding logic
├── email/              # Email validation utilities
├── handler/            # HTTP handlers (decode, validate, respond)
├── metrics/            # Prometheus metrics
├── models/             # Domain entities, value objects, requests, responses
├── ports/              # Interface definitions for external dependencies
├── service/            # Application services (orchestration, domain logic)
├── store/              # Persistence adapters
│   ├── authorization-code/
│   ├── refresh-token/
│   ├── revocation/
│   ├── session/
│   └── user/
└── workers/            # Background workers (cleanup)
```

---

## Aggregates and Invariants

### Session Aggregate (Root)

The **Session** is the primary aggregate root, owning:
- Session lifecycle: `pending_consent` → `active` → `revoked`/`expired`
- Token issuance/refresh coupling (access token JTI tracking, refresh token rotation)
- Device binding state (device ID + fingerprint expectations)

**Intent-revealing methods:**
- `IsActive()`, `IsPendingConsent()`, `IsRevoked()`
- `Activate()` - transitions from pending_consent to active
- `GetDeviceBinding()`, `SetDeviceBinding()` - device binding value object access

**Constructor:** `NewSession()` enforces:
- Scopes cannot be empty
- Status must be valid enum
- ExpiresAt must be after CreatedAt

### Authorization Code (Child Entity)

**AuthorizationCodeRecord** is a child of Session with strict invariants:
- Code is single-use (Used flag prevents replay)
- Expires in 10 minutes
- RedirectURI must match at token exchange

**Constructor:** `NewAuthorizationCode()` enforces:
- Code cannot be empty
- Code is prefixed with `authz_`
- RedirectURI cannot be empty
- ExpiresAt must be after CreatedAt and in the future

**Intent-revealing methods:**
- `IsValid(now)` - not used AND not expired
- `IsExpired(now)` - past expiry time

### Refresh Token (Child Entity)

**RefreshTokenRecord** is a child of Session supporting rotation:
- Token rotates (consume-once via Used flag)
- Expires in 30 days
- Replay of used token indicates potential theft

**Constructor:** `NewRefreshToken()` enforces:
- Token cannot be empty
- ExpiresAt must be after CreatedAt and in the future

**Intent-revealing methods:**
- `IsValid(now)` - not used AND not expired
- `IsExpired(now)` - past expiry time

### User Entity

**User** represents an authenticated identity.

**Constructor:** `NewUser()` enforces:
- Email cannot be empty

**Intent-revealing methods:**
- `IsActive()` - status is active

---

## Domain Services

- **Token Generation** via `TokenGenerator` (`service/token.go`)
- **Device Binding Policy** via `device/device.go` and `service/device_binding.go`
- **Revocation List** via `store/revocation/revocation.go`

These express domain behavior that doesn't naturally live on a single entity.

---

## Transactional Boundaries

The auth service uses transaction boundaries for multi-write operations:

- `AuthStoreTx.RunInTx` wraps multi-store mutations in:
  - `service/token_exchange.go` (consume code + activate session + create refresh token)
  - `service/token_refresh.go` (consume refresh + advance session + create refresh token)

This aligns with Credo's "all multi-write operations must be atomic" rule.

---

## Request Validation Pattern

Requests follow the Normalize/Validate pattern:

```go
type AuthorizationRequest struct { ... }

func (r *AuthorizationRequest) Normalize() {
    // Trim whitespace, set defaults (e.g., default scope to "openid")
}

func (r *AuthorizationRequest) Validate() error {
    // Phase 1: Size validation (fail fast)
    // Phase 2: Required fields
    // Phase 3: Syntax validation (format checks)
    // Phase 4: Semantic validation (in service layer)
}
```

This separates API-input rules (on request structs) from domain invariants (in constructors).

---

## Domain Events / Audit

Audit emissions behave like domain events (emitted on lifecycle transitions):

| Transition            | Audit Action         |
| --------------------- | -------------------- |
| Session created       | `session_created`    |
| Code exchanged        | `token_issued`       |
| Token refreshed       | `token_refreshed`    |
| Token revoked         | `token_revoked`      |
| Session revoked       | `session_revoked`    |

Events are emitted by the service at domain transitions, not by handlers.

---

## Store Error Contract

Stores return sentinel errors from `pkg/platform/sentinel`:
- `ErrNotFound` - entity doesn't exist
- `ErrExpired` - entity has expired
- `ErrAlreadyUsed` - authorization code or refresh token already consumed

Services translate these to domain errors at their boundary.

---

## Testing

| Layer                   | Location                              | Purpose                              |
| ----------------------- | ------------------------------------- | ------------------------------------ |
| Primary (Gherkin)       | `e2e/features/oauth_*.feature`        | Published behavior contracts         |
| Secondary (Integration) | `internal/auth/integration_test.go`   | Multi-component flows                |
| Tertiary (Unit)         | `internal/auth/service/*_test.go`     | Error propagation, edge cases        |

---

## References

- Device Binding: See `../../docs/security/DEVICE_BINDING.md` for the full security model
- Architecture: [docs/engineering/architecture.md](../../docs/engineering/architecture.md)
