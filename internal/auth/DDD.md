# DDD in the Auth Module

This document is a brief Domain‑Driven Design (DDD) primer and a design note for how DDD applies (and should apply) to the `internal/auth` bounded context in Credo.

---

## 1) DDD (Brief)

DDD is an approach to building software where the code structure and language intentionally mirror the business domain. Instead of starting from frameworks or data models, DDD starts from domain concepts and invariants.

### Key concepts (short definitions)

- **Domain**: The problem space (authentication, sessions, tokens, security policy).
- **Subdomain**: A smaller slice of the domain (e.g., authorization code exchange, token refresh, session revocation).
- **Bounded Context**: A boundary in which a domain model and vocabulary are consistent (here: “Auth”).
- **Ubiquitous Language**: Shared, precise terms used in code and discussions (e.g., “authorization code”, “refresh token”, “session”, “revocation”, “consent”).
- **Entity**: Has identity and lifecycle (e.g., `User`, `Session`).
- **Value Object**: Defined by its value, typically immutable (e.g., `Email`, `ClientID`, `ScopeSet`, `RedirectURI`).
- **Aggregate**: A consistency boundary; an aggregate root enforces invariants and is the unit of transactional change (e.g., `Session` as the root for token issuance/refresh state).
- **Domain Invariants**: Rules that must always hold for persisted state; violating them implies corrupted data.
- **Policies / Specifications**: Rules that can change without corrupting stored data (often “API input rules” or “business policy rules”).
- **Repository**: Collection-like interface for aggregates/entities (e.g., `UserStore`, `SessionStore`).
- **Domain Service**: Domain behavior that doesn’t naturally belong on a single entity (e.g., token minting, device binding policy evaluation).
- **Application Service**: Orchestrates use-cases, manages transactions, calls domain services and repositories (e.g., `internal/auth/service.Service`).
- **Domain Events**: sentinel about something that happened (e.g., “session created”, “token issued”) used for audit/async side effects.

---

## 2) Auth Bounded Context: DDD Design (Current + Intended)

### 2.1 Bounded context definition

**Context:** `internal/auth`

**Purpose:** Implement the gateway’s authentication flows and security lifecycle:

- Authorization requests produce authorization codes and sessions
- Token requests exchange codes/refresh tokens for JWTs
- Sessions and tokens can be revoked
- Userinfo is served for authenticated sessions
- Audit/security telemetry is emitted for key transitions

This is a distinct bounded context because its language and invariants are specific: codes, sessions, refresh tokens, consent and revocation are not generic “user management” concerns.

### 2.2 Ubiquitous language mapping (code ↔ terms)

- **User** → `internal/auth/models.User`
- **Session** → `internal/auth/models.Session`
- **Authorization Code** → `internal/auth/models.AuthorizationCodeRecord`
- **Refresh Token** → `internal/auth/models.RefreshTokenRecord`
- **Authorize** use-case → `internal/auth/service/authorize.go`
- **Token exchange / refresh** use-cases → `internal/auth/service/token_exchange.go`, `internal/auth/service/token_refresh.go`
- **Revocation** use-cases → `internal/auth/service/token_revocation.go`, `internal/auth/service/session_revoke.go`
- **UserInfo** use-case → `internal/auth/service/userinfo.go`
- **Audit events** → emitted via `internal/auth/service/service.go#logAudit`

### 2.3 Layering / module roles (what belongs where)

This aligns with Credo’s `AGENTS.md` rules:

- **Handlers** (`internal/auth/handler/*`)
  - HTTP concerns only: decode, basic request validation, context extraction (cookies/headers), response mapping.
- **Application Service** (`internal/auth/service/*`)
  - Orchestration + domain behavior + error mapping, including transaction boundaries via `AuthStoreTx`.
- **Domain Models** (`internal/auth/models/*`)
  - Entities representing persisted auth state (`User`, `Session`, `AuthorizationCodeRecord`, `RefreshTokenRecord`).
- **Stores / Repositories** (`internal/auth/store/*`)
  - Persistence adapters behind interfaces (`UserStore`, `SessionStore`, etc.).

### 2.4 Aggregates and invariants (recommended framing)

**Likely aggregate roots**

- **Session aggregate** (recommended as the primary aggregate root)
  - Owns session lifecycle: pending → active → revoked/expired
  - Owns token issuance/refresh coupling (access token JTI tracking, refresh token rotation)
  - Owns device binding state (device ID + fingerprint expectations)

**AuthorizationCodeRecord** and **RefreshTokenRecord** are best modeled as:

- Entities that are _associated with_ the `Session` aggregate and must obey strict invariants:
  - auth code is single-use, expires, binds to redirect URI
  - refresh token rotates (consume-once), expires, binds to session

**Domain invariants examples (should always hold for stored state)**

- A `Session` must have non-zero `ID`, `UserID`, `CreatedAt`, `ExpiresAt`, and a valid `Status`.
- A `Session` in `active` status must not have `RevokedAt` set.
- A `RefreshTokenRecord` must reference an existing session and must not be reusable.
- An `AuthorizationCodeRecord` must not be usable after expiry and must not be usable more than once.

**Policy / API-input rules (can change without corrupting stored data)**

- Allowed redirect URI schemes (config-based policy).
- Default scopes behavior when none are provided.
- Token TTLs and refresh token TTLs (config-based policy).

### 2.5 Domain services and policies (current)

Current “domain service” style components include:

- **Token generation** via `TokenGenerator` (`internal/auth/service/interfaces.go`)
- **Device binding policy** via `internal/auth/device` and `internal/auth/service/device_binding.go`
- **Revocation list** via `internal/auth/store/revocation` used by the service

These are good DDD fits: they express domain behavior that doesn’t naturally live on a single entity.

### 2.6 Repositories (stores) and transactional boundary (current)

Repositories are expressed as interfaces in `internal/auth/service/interfaces.go`.

The auth service uses a transaction boundary for multi-write operations:

- `AuthStoreTx.RunInTx` wraps multi-store mutations in:
  - `internal/auth/service/token_exchange.go` (consume code + advance session + create refresh token)
  - `internal/auth/service/token_refresh.go` (consume refresh + advance session + create refresh token)

This is aligned with Credo’s atomic multi-write requirement.

### 2.7 Domain events / audit (current)

Audit emissions in `internal/auth/service/service.go#logAudit` behave like _domain events_ (sentinel emitted on lifecycle transitions), but they are not explicitly modeled as domain events in code.

That is acceptable for MVP, but the key DDD intent is: **events are emitted by the service at domain transitions**, not by handlers.

---

## 3) Where the Auth Module Deviates From DDD Norms (and Credo’s invariant/input guidance)

### 3.1 Domain models contain API/validation concerns

`internal/auth/models/models.go` and `internal/auth/models/responses.go` contain `validate:` struct tags (e.g., `internal/auth/models/models.go:12-17`).

- In DDD terms, this couples the domain model to a validation framework (and often to transport concerns).
- In Credo’s `AGENTS.md` terms, validation rules on _domain entities_ are discouraged when they are API-input rules.

**Preferred direction**

- Keep domain invariants enforced at constructors/service boundaries (e.g., `NewSession(...)`, `NewAuthorizationCode(...)`) or at persistence boundaries.
- Keep API request validation on request/command structs (not on persisted entities and not on response DTOs).

### 3.2 Handlers perform business/input defaults

`internal/auth/handler/handler.go` sets default scopes (“openid”) in the handler before calling the service.

- Defaulting is a _use-case rule_ (policy) and should live in the service or in a request “Normalize/Validate” method, not in the HTTP handler.

### 3.3 `internal/auth/models` mixes domain entities with transport DTOs

The package contains:

- persisted entities (`User`, `Session`, `AuthorizationCodeRecord`, `RefreshTokenRecord`)
- API request structs (`AuthorizationRequest`, `TokenRequest`)
- API response structs (`AuthorizationResult`, `TokenResult`, `UserInfoResult`)

DDD doesn’t require separate packages, but mixing them makes it easier to accidentally put API rules onto domain entities (and vice versa).

**Preferred direction**

- Split into `internal/auth/domain` (entities/value objects) and `internal/auth/transport` (requests/responses), or keep `models` but separate files/subpackages by intent (domain vs transport).

### 3.4 Authorization flow multi-write is not transactionally protected

In `internal/auth/service/authorize.go`, the flow performs multiple writes:

- find/create user
- create authorization code
- create session

Token exchange and refresh are wrapped in `RunInTx`, but authorize is not.

If session creation fails after code creation, you can end up with orphaned codes; if user creation succeeds but later steps fail, you can get partial persistence.

This deviates from Credo’s “multi-write must be atomic” rule and from the DDD aggregate/transaction boundary idea.

### 3.5 Invariants are mostly implicit (constructor-less entities)

Entities are instantiated via struct literals throughout the service (e.g., `authorize.go` builds `User`, `Session`, `AuthorizationCodeRecord` directly).

That makes invariants “best-effort” and scattered. In DDD, invariants are ideally enforced in one place (constructor/factory or aggregate root methods).

### 3.6 Domain invariants are partly enforced via request validators

Example: redirect URI parsing and allowed scheme checks happen in `Authorize`, but other invariants (session status transitions, timestamps, required IDs) are assumed correct.

DDD prefers:

- request/command validation for API-input rules
- domain constructors/aggregate methods for invariants

---

## 4) Suggested Refactor Plan (Optional, DDD-aligned)

1. **Remove `validate:` tags from persisted domain entities and response DTOs**
   - Keep validation on request/command structs and/or service boundary checks.
2. **Introduce request normalization/validation methods**
   - e.g., `AuthorizationRequest.Normalize()` (default scopes), `AuthorizationRequest.Validate()`.
3. **Add constructors/factories for key domain objects**
   - e.g., `NewSession(...)`, `NewAuthorizationCode(...)`, `NewRefreshTokenRecord(...)` to enforce invariants centrally.
4. **Make `Authorize` use-case atomic**
   - Extend `AuthStoreTx` (or add a separate tx boundary) so user+code+session writes are all-or-nothing.
5. **Optionally split domain vs transport models**
   - Reduce accidental coupling and keep invariants vs API rules clean.
