# ID Gateway E2E Tests

End-to-end API tests using [godog](https://github.com/cucumber/godog) (Cucumber for Go).

## Why godog?

- ✅ **Native Go**: No separate runtime or language needed
- ✅ **BDD/Cucumber**: Uses Gherkin feature files
- ✅ **Fast**: Runs as Go tests
- ✅ **Simple**: Direct HTTP testing without browser overhead
- ✅ **CI/CD Friendly**: Standard Go test tooling

## Prerequisites

- Go 1.21+
- ID Gateway running on `http://localhost:8080` (or set `BASE_URL`)

## Installation

```bash
cd e2e
go mod download
```

## Running Tests

```bash
# Run all tests
go test -v

# Run with godog options
go test -v --godog.format=pretty

# Run specific feature
go test -v --godog.paths=features/auth_normal_flow.feature

# Run tests with specific tags
go test -v --godog.tags=@normal
go test -v --godog.tags=@security

# Generate report
go test -v --godog.format=cucumber:reports/cucumber.json
```

## Configuration

Set the base URL via environment variable:

```bash
export BASE_URL=http://localhost:8080
go test -v
```

## Project Structure

```
e2e/
├── features/                   # Gherkin feature files
│   ├── auth_normal_flow.feature
│   └── auth_security.feature
├── context.go                  # Test context and HTTP helpers
├── steps.go                    # Step definitions
├── e2e_test.go                # Test runner
├── go.mod
└── README.md
```

## Writing Tests

Feature files use standard Gherkin syntax:

```gherkin
Feature: My Feature
  Scenario: My Test
    Given some precondition
    When I perform an action
    Then I should see a result
```

Step definitions are in `steps.go`:

```go
ctx.Step(`^I POST to "([^"]*)" with body$`, tc.postRequest)
```

## CI/CD Integration

```yaml
- name: Run E2E Tests
  run: |
    go test -v ./e2e/...
  env:
    BASE_URL: http://localhost:8080
```

## Migrated from Playwright

This test suite replaces the Playwright implementation for better:

- Go ecosystem integration
- Simpler dependencies (no Node.js)
- Faster execution
- Better IDE support in Go projects
