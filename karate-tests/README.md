# Credo Karate Test Suite

This is a standalone Karate test suite for black-box testing of Credo OAuth2 API.

## Prerequisites

- Java 11 or higher
- Maven 3.6 or higher
- Credo API running (default: http://localhost:8080)

## Project Structure

```
karate-tests/
├── src/test/java/idgateway/
│   └── IdGatewayRunner.java          # JUnit 5 test runner
├── src/test/resources/
│   ├── idgateway/auth/
│   │   ├── normal_flow.feature       # OAuth2 happy path scenarios
│   │   └── attack_paths.feature      # Security attack simulations
│   └── helpers/
│       ├── pkce.js                   # PKCE generator utilities
│       ├── url-parser.js             # URL parameter extraction
│       └── jwt-decoder.js            # JWT token decoder
├── karate-config.js                  # Global configuration
├── pom.xml                           # Maven dependencies
└── README.md                         # This file
```

## Configuration

The test suite reads configuration from `karate-config.js` and environment variables.

### Environment Variables

- `BASE_URL` - The base URL of Credo API (default: `http://localhost:8080`)

Example:

```bash
export BASE_URL=http://localhost:8080
```

### Test Configuration

Edit `karate-config.js` to modify:

- OAuth2 client credentials
- Test user credentials
- Default headers
- Other test data

## Running Tests

### Run all tests

```bash
cd karate-tests
mvn test
```

### Run specific test suite

```bash
# Run only normal flow tests
mvn test -Dtest=IdGatewayRunner#testNormalFlow

# Run only attack path tests
mvn test -Dtest=IdGatewayRunner#testAttackPaths

# Run all auth tests
mvn test -Dtest=IdGatewayRunner#testAuth
```

### Run with custom BASE_URL

```bash
BASE_URL=https://staging.example.com mvn test
```

### Run specific scenario by tag

```bash
mvn test -Dkarate.options="--tags @security"
```

## Test Suites

### Normal Flow Tests (`normal_flow.feature`)

End-to-end OAuth2 Authorization Code Flow with PKCE:

1. Initiate authorization request
2. Submit login credentials
3. Follow redirect to get authorization code
4. Exchange code for access/refresh tokens
5. Validate token structure
6. Use access token to access protected resources

Additional scenarios:

- Token refresh flow
- Token revocation

### Attack Path Tests (`attack_paths.feature`)

Security-focused simulation tests (tagged with `@security` and `@simulation`):

- **Intercepted authorization code** - Tests PKCE protection
- **Redirect URI manipulation** - Tests strict URI validation
- **Missing PKCE parameters** - Tests PKCE requirement
- **Invalid PKCE challenge method** - Tests S256 requirement
- **Token leakage** - Tests implicit flow prevention
- **Missing state parameter** - Tests CSRF protection
- **Authorization code reuse** - Tests single-use code enforcement
- **Client secret exposure** - Tests public client security

> **Note:** Attack path tests are simulations for validation purposes, not actual exploits.

## Helper Utilities

### PKCE Generator (`helpers/pkce.js`)

Generates cryptographically secure PKCE code verifier and challenge:

```javascript
def codeVerifier = karate.call('classpath:helpers/pkce.js').generateCodeVerifier()
def codeChallenge = karate.call('classpath:helpers/pkce.js').generateCodeChallenge(codeVerifier)
```

### URL Parser (`helpers/url-parser.js`)

Extracts query parameters from URLs:

```javascript
def code = karate.call('classpath:helpers/url-parser.js', { url: redirectUrl, param: 'code' })
```

### JWT Decoder (`helpers/jwt-decoder.js`)

Decodes JWT tokens and returns payload:

```javascript
def payload = karate.call('classpath:helpers/jwt-decoder.js', idToken)
```

## Test Reports

After running tests, reports are available at:

- `target/karate-reports/karate-summary.html` - Summary report
- `target/surefire-reports/` - JUnit XML reports

## Troubleshooting

### Tests fail to connect

- Ensure Credo API is running
- Check the BASE_URL is correct
- Verify network connectivity

### Authentication failures

- Update test credentials in `karate-config.js`
- Ensure test user exists in the system
- Check OAuth2 client is registered

### PKCE errors

- Verify the API supports PKCE (RFC 7636)
- Check code_challenge_method is S256
- Ensure code_verifier matches the challenge

## Development

### Adding New Tests

1. Create a new `.feature` file in `src/test/resources/idgateway/`
2. Add scenarios using Gherkin syntax
3. Reference helpers as needed
4. Add a test method in `IdGatewayRunner.java` if you want to run it separately

### Example Feature File

```gherkin
Feature: My New Test

  Background:
    * url baseUrl

  Scenario: Test something
    Given path '/api/endpoint'
    When method GET
    Then status 200
```

## CI/CD Integration

This test suite can be integrated into CI/CD pipelines:

```yaml
# GitHub Actions example
- name: Run Karate Tests
  run: |
    cd karate-tests
    mvn test
  env:
    BASE_URL: http://localhost:8080
```

## Security Notes

- Attack path tests are **simulations only** - they log expected behavior
- Never run destructive tests against production
- Ensure proper authorization before security testing
- Follow responsible disclosure for any findings

## License

Same as the parent Credo project.
