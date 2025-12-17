## Testing Doctrine

### Purpose

Credo’s tests exist to validate **behavior and contracts**, not implementation details.
Confidence comes from exercising real system boundaries, not from exhaustively unit-testing internals.

---

## Sources of Truth

### 1. Feature Files Are Contracts

* Gherkin feature files define **published behavior**.
* They are the authoritative specification of how Credo behaves externally.
* If behavior matters to users or clients, it belongs in a feature file.

### 2. Cucumber Tests Are Integration Tests

* Cucumber e2e tests that execute real components are considered **integration tests**.
* They validate that the system satisfies its contracts.
* They are the primary source of confidence.

---

## Test Layers and Their Roles

### Primary Layer: Feature-Driven Integration Tests

Use when:

* Behavior is externally observable.
* The behavior can be expressed declaratively.
* The test crosses service, API, or persistence boundaries.

Rules:

* Every feature scenario should map directly to an executable Cucumber test.
* Feature tests should be few, stable, and high signal.
* Do not assert internal state or call sequences.

---

### Secondary Layer: Non-Cucumber Integration Tests

Use sparingly, only when:

* Behavior cannot be expressed cleanly in Gherkin.
* You are testing:

  * concurrency
  * retries
  * shutdown semantics
  * partial failures
  * timing-sensitive behavior

Rules:

* These tests justify their existence explicitly.
* If a behavior can be promoted to a feature file, do so.
* Avoid duplicating feature coverage.

---

### Tertiary Layer: Unit Tests

Unit tests are **exceptions**, not the default.

Allowed use cases:

* Enforcing invariants.
* Edge cases unreachable via integration tests.
* Error mapping and propagation across boundaries.
* Pure functions with meaningful logic.

Disallowed patterns:

* Asserting internal struct fields.
* Verifying function call order.
* Mirroring integration or feature tests.
* Encoding knowledge of internal architecture.

Every unit test must answer:

> “What invariant would break if this test were removed?”

---

## Duplication Policy

* No behavior should be tested at multiple layers without a clear reason.
* When duplication exists:

  * Feature tests win.
  * Lower-level tests are flagged for review, not automatically deleted.

---

## Mocks and Test Doubles

* Avoid mocks by default.
* Use mocks only to:

  * induce failure modes
  * assert error propagation
* Stores, adapters, and transports are replaceable and should not be over-specified.

---

## Conservative Change Policy

* Tests are not deleted by default.
* First classify, then justify any removal or rewrite.
* Prefer refactoring assertions toward contracts over deleting tests outright.

---

## Checklist for Adding a New Test

Before adding a test, ask:

1. Is this behavior already covered by a feature file?
2. Is the behavior externally observable?
3. Can this be expressed declaratively?
4. Does this test assert behavior or implementation?

If the test does not clearly fit a layer, it probably should not exist.
