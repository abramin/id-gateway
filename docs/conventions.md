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

---

## Testing conventions

### Unit testing

- Use `gomock` for stores, clients, publishers.
- Mocks live under `internal/<module>/mocks`.
- Use `testify/assert` and `require`.
- Prefer Given / When / Then structure.
- Use table tests for pure validation logic.

### Integration testing

- Validate end-to-end PRD flows.
- One suite per PRD journey.
- Do not duplicate unit test coverage.
- Focus on HTTP wiring, persistence, and middleware.

---

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

## Mocks and interfaces

- Interfaces live next to their consumers.
- Include `//go:generate mockgen` directives.
- Regenerate mocks when interfaces change and commit together.

---

## References

- `docs/architecture.md`
- `prd/` directory for feature requirements
