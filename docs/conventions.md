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

Yes. The **Testing conventions section needs to be revised** to align with `testing.md` and the updated `AGENTS.md`. Right now it still assumes a classic unit-first posture.

Below is a **surgical rewrite of only the “Testing conventions” section**. Everything else in `conventions.md` can remain unchanged.

I’ll present this as a **drop-in replacement**.

---

## Testing conventions

### Feature-driven integration testing (primary)

* Gherkin feature files define **published behavior and contracts**.
* Cucumber tests that execute real components are considered **integration tests**.
* Feature scenarios should map directly to executable tests.
* Prefer fewer, stable, high-signal scenarios.

Guidelines:

* Assert externally observable behavior only.
* Do not assert internal state, struct fields, or call ordering.
* Treat feature tests as the primary source of confidence.

---

### Non-Cucumber integration testing (secondary)

Used only when behavior:

* cannot be expressed clearly in Gherkin, or
* involves concurrency, retries, shutdown, timing, or partial failure.

Guidelines:

* Each test must justify why it is not a feature scenario.
* Avoid duplicating feature-driven coverage.
* Focus on system boundaries and orchestration risks.

---

### Unit testing (tertiary, exceptional)

Unit tests are **not required for all service logic**.

Allowed use cases:

* Enforcing invariants.
* Edge cases unreachable via integration tests.
* Error mapping and propagation across boundaries.
* Pure functions with meaningful logic.

Guidelines:

* Prefer simple fakes over mocks where possible.
* Use mocks only to induce failure modes or assert error propagation.
* Avoid asserting internal state, orchestration, or implementation detail.
* If a unit test mirrors a feature or integration test, it should be flagged for review.

Every unit test should answer:

> “What invariant or failure mode would escape detection if this test did not exist?”

---

### Tooling and style

* Use `testify/assert` and `require`.
* Prefer Given / When / Then structure for readability.
* Table tests are appropriate for pure validation logic.
* Mocks live under `internal/<module>/mocks` when required.

---

### Duplication policy

* No behavior should be tested at multiple layers without explicit justification.
* Feature-driven tests take precedence.
* Lower-level tests that duplicate feature coverage are candidates for consolidation, not automatic deletion.

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
