# Migration from Karate to Playwright + Cucumber

## Summary

Successfully migrated E2E API tests from Karate to Playwright + Cucumber due to Java compatibility issues.

## Why Migrate?

### Problems with Karate

- ❌ **Java 24 incompatibility**: GraalVM polyglot engine fails with `NoSuchMethodError` on modern Java
- ❌ **Maintenance burden**: Karate 1.4.1 is in maintenance mode, limited updates
- ❌ **Heavy dependencies**: Complex Java/Maven/GraalVM stack
- ❌ **Environment issues**: Requires specific Java versions (11-17)

### Benefits of Playwright

- ✅ **Modern & actively maintained**: Microsoft-backed, frequent updates
- ✅ **No Java required**: Pure Node.js/TypeScript
- ✅ **Better DX**: TypeScript support, excellent error messages, fast execution
- ✅ **Simpler stack**: npm install and you're done
- ✅ **BDD support**: Works seamlessly with Cucumber
- ✅ **Better CI/CD**: Easier to integrate, fewer dependencies

## What Was Migrated

### Test Scenarios (100% coverage)

All Karate feature files were converted to Cucumber/Gherkin:

**Normal Flow Tests** (`normal_flow.feature`):

- ✅ Complete OAuth2 authorization code flow
- ✅ Authorization request validation (missing fields, invalid email, empty scopes)
- ✅ Token exchange validation (invalid codes, wrong grant types)
- ✅ Authorization code reuse prevention
- ✅ UserInfo endpoint access control

**Security Simulations** (`attack_paths.feature`):

- ✅ PKCE attack scenarios (documentation)
- ✅ Redirect URI manipulation
- ✅ CSRF prevention
- ✅ Token leakage prevention
- ✅ Client secret handling

### Test Infrastructure

- Step definitions in TypeScript
- Playwright API request context
- JWT decoding utilities
- Test state management (World)
- Before/After hooks
- HTML reporting

## Directory Structure

### Old (Karate)

```
karate-tests/
├── src/test/
│   ├── java/idgateway/
│   │   └── IdGatewayRunner.java
│   └── resources/
│       ├── idgateway/auth/
│       │   ├── normal_flow.feature
│       │   └── attack_paths.feature
│       └── helpers/
│           ├── pkce.js
│           ├── url-parser.js
│           └── jwt-decoder.js
├── pom.xml
└── karate-config.js
```

### New (Playwright + Cucumber)

```
e2e-tests/
├── features/auth/
│   ├── normal_flow.feature
│   └── attack_paths.feature
├── steps/
│   ├── auth_steps.ts
│   └── simulation_steps.ts
├── support/
│   ├── world.ts
│   └── hooks.ts
├── package.json
├── tsconfig.json
└── cucumber.js
```

## Command Changes

### Before (Karate)

```bash
# Run all tests
make karate

# Using Docker
make karate-docker

# Clean
make karate-clean
```

### After (Playwright)

```bash
# Run all tests
make e2e

# Run specific suites
make e2e-normal      # Normal flow tests only
make e2e-security    # Security simulations only

# Generate HTML report
make e2e-report

# Clean
make e2e-clean
```

## Feature File Conversion Example

### Before (Karate syntax)

```karate
Scenario: Complete OAuth2 authorization code flow
  * def state = java.util.UUID.randomUUID().toString()
  Given path '/auth/authorize'
  And header Content-Type = 'application/json'
  And request { "email": "#(testUser.username)", ... }
  When method POST
  Then status 200
  And match response.code == '#string'
  * def authCode = response.code
```

### After (Cucumber + Playwright)

```gherkin
Scenario: Complete OAuth2 authorization code flow
  Given I generate a random state value
  When I POST to "/auth/authorize" with:
    | email        | test@example.com              |
    | client_id    | test-client                   |
    | scopes       | openid,profile                |
  Then the response status should be 200
  And the response should contain "code"
  And I save the authorization code
```

## Step Definition Example

```typescript
When(
  "I POST to {string} with:",
  async function (path: string, dataTable: DataTable) {
    const data = {};
    for (const [key, value] of dataTable.raw()) {
      data[key] = value === "<authorization_code>" ? this.authCode : value;
    }

    const response = await this.apiContext.post(path, { data });
    this.response = {
      status: response.status(),
      body: await response.json(),
      headers: response.headers(),
    };
  }
);
```

## Installation & Setup

### Prerequisites

```bash
# Node.js 18+
node --version

# Install if needed
brew install node
```

### Install Dependencies

```bash
cd e2e-tests
npm install
```

### Run Tests

```bash
# All tests
npm test

# Tagged tests
npm run test:normal
npm run test:security

# With HTML report
npm run test:report
```

## Environment Configuration

Same as Karate - set `BASE_URL`:

```bash
export BASE_URL=http://localhost:8080
```

Or create `.env` file in `e2e-tests/`:

```
BASE_URL=http://localhost:8080
```

## CI/CD Integration

### GitHub Actions Example

```yaml
- name: Setup Node.js
  uses: actions/setup-node@v4
  with:
    node-version: "20"

- name: Run E2E Tests
  run: make e2e
  env:
    BASE_URL: http://localhost:8080
```

Much simpler than Karate which required Java/Maven setup!

## Next Steps

1. ✅ **Karate removed**: Can delete `karate-tests/` directory
2. ✅ **Makefile updated**: New targets for `e2e` commands
3. ✅ **Dependencies installed**: `npm install` completed
4. ⏭️ **Run tests**: Start backend, then `make e2e`
5. ⏭️ **Update CI/CD**: Replace Karate steps with Playwright

## Rollback (if needed)

The old Karate tests are preserved in `karate-tests/` directory. To revert:

```bash
git checkout Makefile
# Use old make karate commands
```

However, you'll still face Java 24 compatibility issues.

## Resources

- [Playwright Documentation](https://playwright.dev/)
- [Cucumber.js Documentation](https://cucumber.io/docs/cucumber/)
- [Playwright API Testing](https://playwright.dev/docs/api-testing)

## Status

✅ **Migration Complete**

- All test scenarios migrated
- Step definitions implemented
- Makefile targets updated
- Dependencies installed
- Ready to run tests!
