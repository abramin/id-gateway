# Credo Engineering Conventions

This document provides **guidance, rationale, and examples**.
It supports `AGENTS.md` but does not override it.

---

## Architectural intent

Credo is a modular identity and evidence platform built for:

- clarity over cleverness
- strong domain boundaries
- interchangeable infrastructure
- testability by default

## Testing conventions

Testing guidance lives in `docs/engineering/testing.md` and is the source of truth for
layering, contracts, and duplication policy. This document only notes local conventions
not covered there.

## Service construction

- Constructors accept required config plus functional options.
- Required dependencies are validated at construction time.
- Optional fields receive sensible defaults (e.g. TTLs).

---

## Feature flags

- Disabled by default.
- Enabled explicitly per test.
- Use functional options, never globals.

---

## Audit and observability

- Emit audit events at lifecycle transitions.
- Audit logic lives in services.
- Include contextual fields when available:

  - `user_id`
  - `session_id`
  - `client_id`
  - `request_id`

- Use structured logging (`slog`).
- Security events go to both logs and audit streams.

---

## Context usage

- Middleware attaches request metadata to `context.Context`.
- Services read request-scoped data from context.
- Never store sensitive data in context.

---

## Stores and persistence

- SQL implementations should use `sqlc`.
- Store interfaces live with the consuming module.
- Store implementations may differ but behavior must not.

---

## Error handling

Credo uses two error packages with clear boundaries:

### Sentinel errors (`pkg/platform/sentinel`)

**Purpose:** Infrastructure facts returned by stores (persistence layer only).

**Errors:**
- `ErrNotFound` – entity does not exist in store
- `ErrExpired` – token/session/code has expired
- `ErrAlreadyUsed` – resource (auth code, refresh token) already consumed
- `ErrInvalidState` – entity in wrong state for requested operation
- `ErrUnavailable` – service or resource temporarily unavailable

**Usage:**
```go
// In stores
return nil, fmt.Errorf("session not found: %w", sentinel.ErrNotFound)

// In services (check and translate)
if errors.Is(err, sentinel.ErrNotFound) {
    return dErrors.New(dErrors.CodeNotFound, "session not found")
}
```

### Domain errors (`pkg/domain-errors`)

**Purpose:** Business-meaningful errors for services, models, and handlers.

**Usage:**
- Validation in models returns domain-errors directly
- Services translate sentinel errors to domain-errors at their boundary
- Handlers receive domain-errors and map to HTTP responses

```go
// In models (validation)
return dErrors.New(dErrors.CodeValidation, "email is required")

// In services (translation)
if errors.Is(err, sentinel.ErrExpired) {
    return dErrors.New(dErrors.CodeInvalidGrant, "token expired")
}

// Domain errors pass through unchanged
var de *dErrors.Error
if errors.As(err, &de) {
    return err
}
```

### The boundary rule

| Layer | Error Package | Examples |
|-------|---------------|----------|
| Stores (persistence layer) | `sentinel` | `ErrNotFound`, `ErrExpired` |
| Models, services, handlers, JWT | `domain-errors` | `CodeValidation`, `CodeInvalidGrant` |

**Key principle:** Sentinel errors represent infrastructure facts from stores. Domain-errors represent business meaning. Services translate sentinel errors at the boundary.

**Note:** Domain packages that perform validation or business logic (like `jwt_token`, `secrets`) use domain-errors directly. Only pure persistence stores use sentinel.

---

## Mocks and interfaces

- Interfaces live next to their consumers.
- Include `//go:generate mockgen` directives.
- Regenerate mocks when interfaces change and commit together.

---

## References

- `docs/engineering/architecture.md`
- `prd/` directory for feature requirements
