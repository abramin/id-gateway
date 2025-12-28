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
* Organizing top-level tests by method name (e.g., `TestSave`, `TestFind`, `TestDelete`).
* Renaming tests when methods are renamed (sign of implementation coupling).

Every unit test must answer:

> "What invariant would break if this test were removed?"

---

## Test Organization Philosophy

### Name Tests for Behavior, Not Implementation

Tests should describe WHAT the system does, not HOW it does it. This makes tests resilient to refactoring and helps reviewers understand intent.

#### The Refactoring Test

Ask: "If I renamed or split this method, would I need to rename this test?"
- If yes: you may be testing implementation.
- If no: you're testing behavior.

#### Contrast: Method-Based vs Behavior-Based

**Cache example (store layer):**

```go
// METHOD-BASED (mirrors implementation)
// Problem: If we rename SaveCitizen to StoreCitizen, tests break
func (s *CacheSuite) TestSaveCitizen() {
    s.Run("saves citizen record successfully", ...)
    s.Run("overwrites existing record", ...)
}

func (s *CacheSuite) TestFindCitizen() {
    s.Run("returns record when found", ...)
    s.Run("returns ErrNotFound when missing", ...)
}

// BEHAVIOR-BASED (describes capabilities)
// Benefit: Renaming methods doesn't break test organization
func (s *CacheSuite) TestCacheLookups() {
    s.Run("returns record when found and not expired", ...)
    s.Run("returns ErrNotFound when record does not exist", ...)
    s.Run("returns ErrNotFound when record is expired", ...)
}

func (s *CacheSuite) TestCacheWrites() {
    s.Run("stores record retrievable by key", ...)
    s.Run("overwrites record when key exists", ...)
}

func (s *CacheSuite) TestEvictionPolicy() {
    s.Run("evicts LRU entry when at capacity", ...)
    s.Run("access refreshes LRU position", ...)
}
```

### Organization by Module Type

Different module types have different natural groupings:

| Module Type | Group Tests By | Example Names |
|-------------|----------------|---------------|
| Store | Capability / Concern | `TestCacheHitsAndMisses`, `TestEvictionPolicy`, `TestConcurrencySafety` |
| Service | Use Case / Scenario | `TestAuthorizationCodeFlow`, `TestTokenExchange_Validation` |
| Handler | Error Mapping / Validation | `TestGrantConsent_ErrorMapping`, `TestGrantConsent_Validation` |
| Domain | Invariant / State | `TestSessionStateTransitions`, `TestConsentExpiration` |
| Pure Function | Input Category | `TestParseNationalID_ValidFormat`, `TestParseNationalID_InvalidLength` |

### When Method-Based Is Acceptable

Method-based naming is appropriate when:

1. **The method name IS the behavior** - `ParseNationalID` describes what happens
2. **Testing interface compliance** - verifying a type implements Store correctly
3. **Pure functions with self-documenting names** - `ComputeFingerprint`
4. **Single-purpose types** - when a type has one method that IS its purpose

```go
// ACCEPTABLE: The method name describes the behavior completely
func TestParseNationalID(t *testing.T) {
    t.Run("accepts valid 9-character ID", ...)
    t.Run("rejects ID shorter than 6 characters", ...)
}

// ACCEPTABLE: Testing Store interface compliance
func TestMemoryStore_ImplementsStore(t *testing.T) {
    var _ Store = (*MemoryStore)(nil)
}
```

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

## Test Structure Patterns

### Test Suites (Default)

Use testify test suites by default for testing a type or module with multiple methods or behaviors:

```go
type ServiceSuite struct {
    suite.Suite
}

func TestServiceSuite(t *testing.T) {
    suite.Run(t, new(ServiceSuite))
}

func (s *ServiceSuite) TestMethodBehavior() {
    s.Run("variation one", func() {
        // Use s.Require(), s.Assert(), s.Equal(), etc.
        s.Require().NoError(err)
        s.Equal(expected, actual)
    })

    s.Run("variation two", func() {
        s.Assert().True(condition)
    })
}
```

Suite benefits:
* Shared setup/teardown via `SetupTest()`, `TearDownTest()`
* Consistent assertion style with `s.Require()`, `s.Assert()`
* Subtests via `s.Run()` for method variations

### Subtests for Method Variations

Use `s.Run()` or `t.Run()` when testing different scenarios of the same method:

```go
func (s *ServiceSuite) TestLookup() {
    s.Run("returns cached record when available", func() { ... })
    s.Run("fetches from provider when cache miss", func() { ... })
    s.Run("handles provider timeout", func() { ... })
}
```

### Single Tests Without Suites

For isolated tests with no shared state or related variations, use plain test functions:

```go
func TestParseNationalID_ValidFormat(t *testing.T) {
    id, err := ParseNationalID("ABC123456")
    require.NoError(t, err)
    assert.Equal(t, "ABC123456", id.String())
}
```

### Table Tests (Narrow Use)

Only use table-driven tests when calling the same method with a single parameter change:

```go
// GOOD: Single parameter varies (status code)
func TestParser_RejectsNon200Status(t *testing.T) {
    codes := []int{400, 401, 404, 500, 503}
    for _, code := range codes {
        t.Run(fmt.Sprintf("status_%d", code), func(t *testing.T) {
            _, err := parseResponse(code, []byte(`{}`))
            assert.Error(t, err)
        })
    }
}

// BAD: Multiple parameters and complex assertions - use subtests instead
func TestParser_Various(t *testing.T) {
    tests := []struct {
        name       string
        statusCode int
        body       []byte
        wantErr    bool
        wantData   map[string]any
    }{ ... }  // Don't do this
}
```

When multiple parameters vary or assertions differ per case, use explicit subtests for clarity.

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
