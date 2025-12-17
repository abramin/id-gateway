# Credo Agent Rules (Authoritative)

This file defines **non-negotiable rules** that all code generated or modified by agents must follow.
If a rule here conflicts with any other document, this file wins.

---

## Non-negotiable rules

- No business logic in handlers.
- No globals.
- Services own orchestration and domain behavior.
- Domain entities do not contain API input rules.
- Stores return domain models, never persistence structs.
- Internal errors are never exposed to clients.
- All multi-write operations must be atomic.

---

## Module structure

### Handlers

- Handle HTTP concerns only: parsing, request validation, response mapping.
- Always accept and pass through `context.Context`.

### Services

- All business logic lives in services.
- Depend only on interfaces.
- Validate domain invariants.
- Perform orchestration and error mapping.

### Models

- Domain models represent persisted state.
- No API input rules on domain entities.
- Request/command structs may contain `Validate()` methods.

### Stores

- Interfaces only.
- Must be swappable (in-memory, SQL, etc.).
- Return domain models.

---

## Validation placement

### Domain invariants

- Rules that must _always_ hold for an entity.
- Violations mean corrupted state.
- Enforced via constructors or persistence boundaries.

### API input rules

- Rules specific to an API, flow, or version.
- May change without data migration.
- Enforced on request/command structs or in services.

**Rule of thumb**  
If a rule can change without invalidating stored data, it is an API input rule.

Example:  
A `Client` must always have a non-nil `TenantID` (domain invariant), but redirect URI scheme rules are API input rules.

---

## Entity state

- Entity lifecycle state (e.g. Session status) must be modeled using
  closed sets (typed constants or value objects), never magic strings
  or booleans. State transitions are enforced in services or entities.

## Error handling

- Use domain error codes via `pkg/domain-errors`.
- Map store or infra errors to domain errors at the service boundary.
- Never leak internal error details.

---

## Transactions

- Use `RunInTx` for multi-store writes.
- Avoid partial persistence on failure.
- Token, session, and audit updates must be atomic.

---

## Testing (authoritative rules)

Testing in Credo follows a **contract-first, behavior-driven approach**.

### Sources of truth

* Gherkin **feature files are the authoritative contracts**.
* Cucumber tests that execute real components are considered **integration tests**.
* Feature-driven integration tests define correctness.

---

### Test layers and intent

#### Feature-driven integration tests (primary)

* Validate externally observable behavior.
* Execute real system boundaries.
* Must map directly to feature scenarios.
* Define correctness for the system.

If behavior matters to users or clients, it belongs here.

---

#### Non-Cucumber integration tests (secondary)

Allowed only when behavior:

* cannot be expressed clearly in Gherkin, or
* involves concurrency, shutdown, retries, timing, or partial failure.

These tests must justify why they are not feature scenarios.

---

#### Unit tests (tertiary, exceptional)

Unit tests are **not required for all service logic**.

They exist only to:

* enforce invariants
* validate edge cases unreachable via integration tests
* assert error propagation or mapping across boundaries
* test pure functions with meaningful logic

Unit tests must **not**:

* assert internal state or struct fields
* encode call ordering or orchestration
* duplicate feature or integration coverage

Every unit test must answer:

> “What invariant would break if this test were removed?”

---

### Duplication policy

* No behavior should be tested at multiple layers without justification.
* Feature tests take precedence.
* Lower-level tests that duplicate feature coverage are flagged for review, not deleted by default.

---

### Mocks and doubles

* Avoid mocks by default.
* Use mocks only to induce failure modes or validate error propagation.
* Stores, adapters, and transports must remain swappable.

---

### Conservative posture

* Tests are not deleted automatically.
* First classify, then justify rewrite or removal.
* Prefer rewriting tests toward contract assertions.

---

### Additional conventions

- see docs/conventions.md
