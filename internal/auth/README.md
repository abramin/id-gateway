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

This is a distinct bounded context because its language and invariants are specific: codes, sessions, refresh tokens, device binding, and revocation are not generic "user management" concerns.

---

## Ubiquitous Language

| Domain Term            | Code Location                                  |
| ---------------------- | ---------------------------------------------- |
| **User**               | `models.User`                                  |
| **Session**            | `models.Session`                               |
| **Authorization Code** | `models.AuthorizationCodeRecord`              |
| **Refresh Token**      | `models.RefreshTokenRecord`                    |
| **Authorize**          | `service/authorize.go`                         |
| **Token exchange**     | `service/token_exchange.go`                    |
| **Token refresh**      | `service/token_refresh.go`                     |
| **Revocation**         | `service/token_revocation.go`, `service/session_revoke.go` |
| **UserInfo**           | `service/userinfo.go`                          |
| **Device Binding**     | `device/device.go`, `service/device_binding.go` |
| **Revocation Reason**  | `models.RevocationReason`                       |
| **Audit events**       | emitted via `service/observability.go#logAudit` |

> **Architecture Note:** Device ID cookie extraction happens in middleware (cross-cutting), while cookie setting happens in the auth handler (business logic). See `docs/engineering/architecture.md` for rationale.

---

## Module Structure

```
internal/auth/
├── adapters/           # External service adapters (ratelimit, resilient client resolver)
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
- Session lifecycle: `pending_consent` -> `active` -> `revoked` (terminal)
- Token issuance/refresh coupling (access token JTI tracking, refresh token rotation)
- Device binding state (device ID + fingerprint expectations)

**Expiration model:** Sessions are time-bound via `ExpiresAt` and rejected by store checks when expired. Expiration is not a status value; the cleanup worker deletes expired sessions.

**Intent-revealing methods:**
- `IsActive()`, `IsPendingConsent()`, `IsRevoked()` - status predicates
- `Activate()` - transitions from pending_consent to active
- `CanAdvance(allowPending)` - checks state for token operations
- `Revoke(at)` - transitions to revoked state, returns false if already revoked
- `RecordActivity(at)` - updates LastSeenAt if time is after current value
- `RecordRefresh(at)` - updates LastRefreshedAt and calls RecordActivity
- `ApplyTokenJTI(jti)` - records the latest access token JTI
- `ApplyDeviceInfo(deviceID, fingerprintHash)` - updates device binding fields
- `ValidateForAdvance(clientID, at, allowPending)` - validates session state for token operations
- `GetDeviceBinding()`, `SetDeviceBinding()` - device binding accessors

**Constructor:** `NewSession()` enforces:
- Scopes cannot be empty
- Status must be valid enum
- `ExpiresAt` must be after `CreatedAt`

**Default TTLs (configurable):**
- Session TTL: 24 hours (`SESSION_TTL`)

### Authorization Code (Child Entity)

**AuthorizationCodeRecord** is a child of Session with strict invariants:
- Code is single-use (Used flag prevents replay)
- Expires in 10 minutes (hard-coded in `Authorize`)
- RedirectURI must match at token exchange

**Constructor:** `NewAuthorizationCode()` enforces:
- Code cannot be empty (no required prefix)
- RedirectURI cannot be empty
- `ExpiresAt` must be after `CreatedAt` and not in the past

**Intent-revealing methods:**
- `IsValid(now)` - not used AND not expired
- `IsExpired(now)` - past expiry time
- `MarkUsed()` - marks as used for replay prevention, returns false if already used
- `ValidateForConsume(redirectURI, now)` - validates code can be consumed (redirect match, not expired, not used)

### Refresh Token (Child Entity)

**RefreshTokenRecord** is a child of Session supporting rotation:
- Token rotates (consume-once via Used flag)
- Expires in 30 days by default (configurable via service config)
- Replay of used token indicates potential theft (revokes session)

**Constructor:** `NewRefreshToken()` enforces:
- Token cannot be empty
- `ExpiresAt` must be after `CreatedAt` and not in the past

**Intent-revealing methods:**
- `IsValid(now)` - not used AND not expired
- `IsExpired(now)` - past expiry time
- `MarkUsed(at)` - marks as used for rotation tracking, records LastRefreshedAt
- `ValidateForConsume(now)` - validates token can be consumed (not expired, not used)

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
  - Device binding is logging-only unless `DeviceBindingEnabled` is true.
  - Fingerprints are hashed; no IP is stored.
- **Revocation List** via `store/revocation` (PostgreSQL-backed in production)
  - `TRLFailureMode` controls whether TRL write failures warn or fail.
  - Clock injection via `WithClock(func() time.Time)` option for testability
- **Replay Protection** via `service/token_flow.go#revokeSessionOnReplay`
  - Shared helper for replay attack handling in both code exchange and token refresh flows
  - Revokes associated session when `ErrAlreadyUsed` is detected

These express domain behavior that doesn't naturally live on a single entity.

---

## Store Boundary Pattern

Stores delegate validation to domain entity methods rather than implementing validation inline:

```go
// Store calls domain validation method
func (s *Store) ConsumeAuthCode(ctx, code, redirectURI, now) (*AuthorizationCodeRecord, error) {
    record := s.findByCode(code)
    if err := record.ValidateForConsume(redirectURI, now); err != nil {
        return record, translateToDomainError(err)
    }
    record.MarkUsed()
    return record, nil
}
```

**Benefits:**
- Domain invariants live in domain entities, not scattered across stores
- Single source of truth for validation logic
- Easier to test domain rules in isolation
- Stores remain thin persistence adapters

---

## Transactional Boundaries

The auth service uses transaction boundaries for multi-write operations:

- `AuthStoreTx.RunInTx` wraps multi-store mutations in:
  - `service/token_exchange.go` (consume code + activate session + create refresh token)
  - `service/token_refresh.go` (consume refresh + advance session + create refresh token)

Token artifacts are generated before writes to avoid partial state if token creation fails.

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
    // Phase 4: Semantic validation (service layer)
}
```

This separates API-input rules (on request structs) from domain invariants (in constructors).

---

## Security Features

- **Redirect URI validation**: scheme allowlist (`AllowedRedirectSchemes`, defaults to https; http allowed in local/demo) and exact match against registered client URIs.
- **Authorization code replay protection**: used codes revoke the session to mitigate theft.
- **Refresh token rotation**: used tokens revoke the session (replay detection).
- **Access token revocation**: JTI stored in TRL with TTL; failures default to warn mode.
- **Device binding signals**: cookie device ID + hashed fingerprint; drift/mismatch logged when enabled.
- **Consistent error handling**: domain errors map to safe HTTP responses; internal errors are not exposed.

---

## Domain Events / Audit

Audit emissions behave like domain events (emitted on lifecycle transitions):

| Transition                | Audit Action          |
| ------------------------- | --------------------- |
| User created              | `user_created`        |
| Session created           | `session_created`     |
| Token issued              | `token_issued`        |
| Token refreshed           | `token_refreshed`     |
| Token revoked             | `token_revoked`       |
| Session revoked           | `session_revoked`     |
| Sessions revoked (admin)  | `sessions_revoked`    |
| User deleted              | `user_deleted`        |
| Userinfo accessed         | `userinfo_accessed`   |
| Auth failure              | `auth_failed`         |

Events are emitted by the service at domain transitions, not by handlers.

---

## Store Error Contract

Stores return sentinel errors from `pkg/platform/sentinel`:
- `ErrNotFound` - entity doesn't exist
- `ErrExpired` - entity has expired
- `ErrAlreadyUsed` - authorization code or refresh token already consumed

Services translate these to domain errors at their boundary.

---

## Product Notes

- OAuth 2.0 authorization code flow issues JWT access tokens (15 minutes by default) and rotating refresh tokens (30 days by default).
- Per-tenant issuer URLs are derived from `JWT_ISSUER_BASE_URL` and tenant ID.
- Device binding signals are collected for drift/mismatch detection; enforcement is opt-in.

---

## HTTP Endpoints

- `POST /auth/authorize`
- `POST /auth/token`
- `POST /auth/revoke`
- `GET /auth/userinfo`
- `GET /auth/sessions`
- `DELETE /auth/sessions/{session_id}`
- `DELETE /admin/auth/users/{user_id}`

---

## Design Rationale

- Authorization codes prevent tokens from appearing in browser logs and history.
- Separate models for sessions, codes, and refresh tokens keep lifetimes and invariants clear.
- Device fingerprints are hashed to avoid storing raw browser data.

---

## Known Gaps / Follow-ups

- Password authentication not implemented (email-only demo flow).
- Multi-factor authentication deferred.
- Self-service account deletion deferred.
- Device binding is logging-only unless `DeviceBindingEnabled` is true.
- Admin deletion is not transactional across stores.

---

## Testing

| Layer                   | Location                               | Purpose                              |
| ----------------------- | -------------------------------------- | ------------------------------------ |
| Primary (Gherkin)       | `e2e/features/auth_*.feature`          | Published behavior contracts         |
| Secondary (Integration) | `internal/auth/integration_test.go`    | Multi-component flows                |
| Tertiary (Unit)         | `internal/auth/service/*_test.go`      | Error propagation, edge cases        |

Primary tests include:
- `e2e/features/auth_normal_flow.feature`
- `e2e/features/auth_token_lifecycle.feature`
- `e2e/features/auth_security.feature`

---

## References

- Device Binding: See `docs/security/DEVICE_BINDING.md`
- Architecture: `docs/engineering/architecture.md`
