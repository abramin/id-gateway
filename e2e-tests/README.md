# ID Gateway E2E Tests

Modern API testing suite using Playwright + Cucumber for the ID Gateway OAuth2 service.

## Prerequisites

- Node.js 18+
- npm or yarn

## Installation

```bash
cd e2e-tests
npm install
```

## Configuration

Set the base URL via environment variable (defaults to `http://localhost:8080`):

```bash
export BASE_URL=http://localhost:8080
```

## Running Tests

```bash
# Run all tests
npm test

# Run only normal flow tests
npm run test:normal

# Run only security simulation tests
npm run test:security

# Generate HTML report
npm run test:report
```

## Project Structure

```
e2e-tests/
├── features/           # Cucumber feature files (Gherkin)
│   └── auth/
│       ├── normal_flow.feature    # OAuth2 happy path scenarios
│       └── attack_paths.feature   # Security simulations
├── steps/              # Step definitions (TypeScript)
│   ├── auth_steps.ts
│   └── simulation_steps.ts
├── support/            # Test helpers and world
│   ├── world.ts        # Test context/state
│   └── hooks.ts        # Before/After hooks
├── reports/            # Test reports (generated)
├── package.json
├── tsconfig.json
└── cucumber.js         # Cucumber configuration
```

## Features

### Normal Flow Tests (`@normal`)

End-to-end OAuth2 Authorization Code Flow scenarios:

- Complete authorization flow with token exchange
- Request validation (missing fields, invalid email, empty scopes)
- Token exchange validation (invalid codes, wrong grant types)
- Authorization code reuse prevention
- UserInfo endpoint access control

### Security Simulations (`@security`)

Documentation scenarios for future security implementations:

- PKCE attack scenarios (when PKCE is implemented)
- Redirect URI manipulation
- CSRF prevention via state parameter
- Token leakage prevention
- Client secret handling for public clients

## Writing Tests

Step definitions use Playwright's API request context:

```typescript
When(
  "I POST to {string} with:",
  async function (path: string, dataTable: DataTable) {
    const response = await this.apiContext.post(path, { data });
    this.response = {
      status: response.status(),
      body: await response.json(),
      headers: response.headers(),
    };
  }
);
```

## CI/CD Integration

Add to your CI pipeline:

```yaml
- name: Run E2E Tests
  run: |
    cd e2e-tests
    npm install
    npm test
  env:
    BASE_URL: http://localhost:8080
```

## Migrated from Karate

This test suite replaces the previous Karate implementation and provides:

- Better Java/GraalVM compatibility (none needed!)
- Faster execution
- Modern tooling and IDE support
- TypeScript type safety
- Cleaner, more maintainable code
