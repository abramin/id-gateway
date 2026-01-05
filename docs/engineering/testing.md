# Credo Testing Philosophy: Inverted Pyramid

## The Traditional Pyramid (and why we invert it)

Traditional wisdom says: many unit tests, fewer integration tests, even fewer E2E tests.

**We invert this for identity systems because:**

1. **Correctness lives at boundaries.** A token that validates in isolation but fails at the HTTP layer is worthless. A consent that persists correctly but can't be queried is broken.

2. **Mocks lie.** A unit test with mocked dependencies proves your code works with your mock, not with the real system. Identity flows fail at integration points—clock skew, transaction isolation, network partitions.

3. **Refactoring should be free.** If renaming a method breaks 50 unit tests but behavior is unchanged, your tests are testing implementation, not contracts.

4. **Security invariants span layers.** "Token cannot be replayed" is not a unit-testable property—it requires HTTP parsing, storage lookup, and time comparison working together.

---

## The Inverted Pyramid

```
        ┌─────────────────────────────────┐
        │     Feature / Contract Tests     │  ← Most tests here
        │   (Gherkin scenarios, OpenAPI)   │
        ├─────────────────────────────────┤
        │      Integration Tests           │  ← Hit real boundaries
        │  (HTTP, DB, adapters, timing)    │
        ├─────────────────────────────────┤
        │         Unit Tests               │  ← Fewest, must justify
        │   (Invariants, pure domain)      │
        └─────────────────────────────────┘
```

---

## When to write each type

### Feature / Contract Tests (default)

**Write these first. They are the source of truth.**

Feature tests answer: "Does the system behave correctly from a user's perspective?"

**Use for:**

- Every user-visible behavior (auth flows, consent grants, token issuance)
- Every state transition in the domain (session created → active → revoked)
- Every error the user can observe (invalid redirect URI, expired token, missing scope)
- Protocol compliance (OAuth/OIDC spec requirements)

**Format:** Gherkin scenarios in `.feature` files

```gherkin
Scenario: Token cannot be used after revocation
  Given a valid access token for user "alice"
  When the token is revoked
  And the token is used to access a protected resource
  Then the response status is 401
  And the error is "token_revoked"
```

**The test:**

- Hits real HTTP endpoints
- Uses real database
- Exercises real token validation

**Not mocked:** Storage, crypto, time (use test clock, not mock clock)

---

### Integration Tests (for what features can't cover)

Integration tests answer: "Do the components work together under stress, timing, and failure conditions?"

**Use for:**

- Concurrency (parallel token refresh, race to revoke)
- Timing (clock skew, expiry edge cases, TTL boundaries)
- Partial failure (DB timeout mid-transaction, network partition)
- Retry behavior (idempotency under duplicate requests)
- Shutdown (graceful drain, in-flight request handling)
- Cache coherence (invalidation timing, stampede protection)

**Format:** Go test suites with real infrastructure

```go
func (s *TokenSuite) TestConcurrentRefreshDoesNotDuplicateTokens() {
    s.Run("parallel refresh requests return same token", func() {
        // Hit real HTTP, real DB, real token store
        // Assert only one token created
    })
}
```

**Why not feature tests?** Gherkin can't express "50 concurrent requests" or "kill the DB connection mid-write" cleanly.

**Not mocked:** Infrastructure. Use testcontainers or embedded stores.

---

### Unit Tests (exceptional, must justify)

Unit tests answer: "Does this specific invariant hold in isolation?"

**The justification question:** _"What invariant breaks if this test is removed, and why can't an integration test catch it?"_

**Use for:**

- **Pure domain logic** that is computationally complex
  - Scope parsing and matching
  - Token claim validation rules
  - Consent overlap detection
- **Invariants unreachable via integration**
  - Edge cases in `Parse*` functions (malformed input variations)
  - State machine transitions that require specific setup
- **Error mapping at boundaries**
  - Domain error → HTTP status mapping
  - Store sentinel → domain error translation

**Format:** Go test suites, no mocks of domain types

```go
func (s *ScopeSuite) TestScopeMatching() {
    s.Run("requested subset of granted scopes is allowed", func() {
        granted := scope.MustParse("read write delete")
        requested := scope.MustParse("read write")
        s.True(granted.Covers(requested))
    })

    s.Run("requested superset of granted scopes is denied", func() {
        granted := scope.MustParse("read")
        requested := scope.MustParse("read write")
        s.False(granted.Covers(requested))
    })
}
```

**Why unit here?** Pure function, many edge cases, no I/O involved. Integration test would just add noise.

---

## Decision flowchart

```
Is this user-visible behavior?
    ├─ Yes → Feature test (Gherkin)
    └─ No ↓

Is this about concurrency, timing, failure, or shutdown?
    ├─ Yes → Integration test
    └─ No ↓

Is this a pure domain invariant with many edge cases?
    ├─ Yes → Unit test (justify in comment)
    └─ No ↓

Is this error mapping at a boundary?
    ├─ Yes → Unit test (justify in comment)
    └─ No ↓

Do you actually need a test?
    └─ Maybe the feature test already covers it.
```

---

## What we don't test (or test minimally)

### No tests for:

- Struct field existence (compiler catches this)
- Constructor calls with valid input (feature tests cover happy path)
- "Does the mock return what I told it to" (tautology)
- Third-party library behavior (trust or vendor)

### Minimal tests for:

- HTTP handler routing (one test per route to prove wiring, not logic)
- Store CRUD (one test per operation type, not per entity)
- Config parsing (one test proving it loads, not every field)

---

## Mock policy

**Mocks are allowed only to induce failure modes.**

| Scenario                                  | Mock allowed? | Why                                      |
| ----------------------------------------- | ------------- | ---------------------------------------- |
| Test happy path token issuance            | ❌            | Use real store, real crypto              |
| Test behavior when DB is down             | ✅            | Need to simulate unavailability          |
| Test behavior when external IDP times out | ✅            | Can't reliably make real IDP timeout     |
| Test token validation logic               | ❌            | Use real token, real validator           |
| Test retry on transient failure           | ✅            | Need to control failure/success sequence |

**Never mock:**

- Domain types (entities, value objects, aggregates)
- Time (use test clock that you control, not mock)
- Crypto (use real crypto with test keys)
- The thing you're testing

---

## Test naming reflects this philosophy

Tests are named for **behavior**, not **implementation**:

```go
// ❌ Implementation-coupled (breaks on refactor)
func TestTokenService_ValidateToken() { ... }
func TestTokenStore_FindByJTI() { ... }

// ✅ Behavior-coupled (survives refactor)
func TestTokenValidation_RejectsExpiredTokens() { ... }
func TestTokenValidation_RejectsRevokedTokens() { ... }
func TestTokenValidation_AcceptsValidTokenWithRequiredScopes() { ... }
```

---

## Coverage philosophy

**We don't target a coverage percentage.** Coverage is a signal, not a goal.

Instead, we target:

- **100% of user-visible behaviors** have feature tests
- **100% of documented error codes** are exercised by tests
- **100% of state transitions** are tested (can enter, can exit, no trapdoors)
- **Every security invariant** has at least one test that would fail if violated

Low coverage in a file might mean:

- Dead code (delete it)
- Trivial code (acceptable)
- Missing tests (investigate)

High coverage with bad tests is worse than low coverage with good tests.

---

## Relationship to agents

| Agent                | Testing implication                                                     |
| -------------------- | ----------------------------------------------------------------------- |
| **QA**               | Every CONTRACT finding becomes a feature scenario                       |
| **Secure-by-design** | Every SECURITY invariant gets a test proving enforcement                |
| **DDD**              | Pure domain logic may warrant unit tests for complex invariants         |
| **Balance**          | EFFECTS violations ("scattered I/O") make testing hard—fix design first |
| **Performance**      | Load test scenarios validate PERFORMANCE assumptions                    |
| **Testing**          | Translates all of the above into actual test code                       |

---

## Summary

1. **Feature tests are the default.** If it's user-visible, it's a Gherkin scenario.
2. **Integration tests cover the hard parts.** Concurrency, timing, failure, shutdown.
3. **Unit tests are exceptional.** Every one must answer: "What invariant, and why not integration?"
4. **Mocks induce failures only.** Happy paths use real components.
5. **Name tests for behavior.** Refactoring should not break tests.
6. **Coverage is a signal, not a target.** Behaviors covered matters more than lines covered.
