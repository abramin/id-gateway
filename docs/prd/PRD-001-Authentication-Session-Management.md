# PRD-001: Authentication & Session Management

**Status:** Implementation Required
**Priority:** P0 (Critical)
**Owner:** Engineering Team
**Last Updated:** 2025-12-03

---

## 1. Overview

### Problem Statement

The ID Gateway requires a lightweight authentication system that manages user identities and sessions without implementing a full OAuth2/OIDC stack. Users need to authenticate, receive tokens, and access their profile information through standard endpoints.

### Goals

- Implement OIDC-lite authentication flow (OAuth2 + minimal identity layer)
- Manage user lifecycle (creation, retrieval, profile access)
- Handle session creation and validation
- Issue access and ID tokens for authenticated users
- Provide userinfo endpoint for profile claims

### Non-Goals

- Full OIDC certification compliance
- Social login integration (Google, Facebook, etc.)
- Password management (passwords not required for demo)
- Multi-factor authentication
- JWT signing with real cryptography (use simple tokens for MVP)

---

## 2. User Stories

**As a** client application
**I want to** authenticate users via email
**So that** I can identify who is making requests

**As a** user
**I want to** obtain access tokens after authentication
**So that** I can access protected resources

**As a** client application
**I want to** retrieve user profile information
**So that** I can display user details and personalize the experience

---

## 2.1. OAuth2 Flow Support

This implementation follows the standard **OAuth 2.0 Authorization Code Flow** (RFC 6749) with the following parameters:

**redirect_uri**

- Required for browser-based flows where the user is redirected back to the client application after authentication
- The gateway appends the `code` (authorization code) and `state` as query parameters to this URI
- Client applications extract the code and exchange it for tokens via the token endpoint
- Optional: If not provided, the response contains only the authorization code

**state**

- CSRF protection token provided by the client
- The gateway echoes this value back in the redirect_uri
- Client must validate the state matches before using the authorization code
- Prevents authorization code injection attacks
- Optional but strongly recommended for security

**code (Authorization Code)**

- Short-lived, single-use credential issued by the authorization endpoint
- Client exchanges this code for access and ID tokens at the token endpoint
- Expires after 10 minutes if not used
- Cannot be reused (marked as consumed after exchange)

**Example browser-based flow:**

1. Client redirects user to: `POST /auth/authorize` with redirect_uri, state, and scopes
2. Gateway creates session internally, responds with: `{"redirect_uri": "https://client.com/callback?code=abc123&state=xyz"}`
3. Client redirects user to the returned redirect_uri
4. Client validates state matches, extracts authorization code
5. Client calls `POST /auth/token` with grant_type=authorization_code and code to get tokens

---

## 3. Functional Requirements

### FR-1: User Authorization

**Endpoint:** `POST /auth/authorize`

**Description:** Initiate an authentication session for a user by email. If the user doesn't exist, create them automatically. Returns an authorization code following OAuth 2.0 specification.

**Input:**

```json
{
  "email": "user@example.com",
  "client_id": "demo-client",
  "scopes": ["openid", "profile"], // Optional, defaults to ["openid"]
  "redirect_uri": "https://app.example.com/callback", // Required for code flow
  "state": "xyz123" // Optional, CSRF protection (strongly recommended)
}
```

**Output (Success - 200):**

```json
{
  "code": "authz_abc123xyz",
  "redirect_uri": "https://app.example.com/callback?code=authz_abc123xyz&state=xyz123"
}
```

**Business Logic:**

1. Validate email format
2. Validate redirect_uri format (must be valid HTTPS URL, or HTTP for localhost only)
3. Validate client_id is provided and non-empty
4. Check if user exists by email
5. If not exists, create new user with:
   - Generated unique ID (UUID)
   - Email as provided
   - FirstName/LastName extracted from email (before @)
   - Verified = false
6. If exists, retrieve user
7. Generate authorization code:
   - Format: `authz_<uuid>` (e.g., `authz_550e8400-e29b-41d4-a716-446655440000`)
   - Store code expiry: current time + 10 minutes
8. Create new session with:
   - Generated unique ID (UUID)
   - UserID from step 4/5
   - Authorization code from step 7
   - RequestedScope from input (default to ["openid"] if empty)
   - Status = "pending_consent"
   - ClientID from input
   - RedirectURI from input (stored for validation at token exchange)
   - CreatedAt = current timestamp
   - CodeExpiresAt = current timestamp + 10 minutes
9. Save session to SessionStore
10. Build redirect_uri response:
    - Append code and state as query parameters
    - If state provided: echo it back in response for CSRF validation
11. Return authorization code and complete redirect_uri

**Error Cases:**

- 400 Bad Request: Invalid email format
- 400 Bad Request: Invalid redirect_uri format
- 500 Internal Server Error: Store failure

---

### FR-2: Token Exchange

**Endpoint:** `POST /auth/token`

**Description:** Exchange a valid authorization code for access and ID tokens following OAuth 2.0 specification.

**Input:**

```json
{
  "grant_type": "authorization_code",
  "code": "authz_abc123xyz",
  "redirect_uri": "https://app.example.com/callback",
  "client_id": "demo-client"
}
```

**Output (Success - 200):**

```json
{
  "access_token": "at_550e8400-e29b-41d4-a716-446655440000",
  "id_token": "idt_550e8400-e29b-41d4-a716-446655440000",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**Business Logic:**

1. Validate grant_type is "authorization_code"
2. Validate code, redirect_uri, and client_id are provided
3. Find session by authorization code in SessionStore
4. If session not found, return 401 (invalid code)
5. Validate authorization code has not expired (< 10 minutes old)
6. Validate authorization code has not been used before (prevent replay attacks)
7. Validate redirect_uri matches the one stored in session (OAuth 2.0 requirement)
8. Validate client_id matches the one stored in session
9. Mark authorization code as used in session (set CodeUsed = true)
10. Generate access_token as: `"at_" + session.ID`
11. Generate id_token as: `"idt_" + session.ID`
12. Set token expiry: expires_in = 3600 (1 hour)
13. Update session status to "active"
14. Save updated session
15. Return tokens

**Error Cases:**

- 400 Bad Request: Missing required fields (grant_type, code, redirect_uri, client_id)
- 400 Bad Request: Unsupported grant_type (must be "authorization_code")
- 401 Unauthorized: Invalid authorization code (not found)
- 401 Unauthorized: Authorization code expired (> 10 minutes old)
- 401 Unauthorized: Authorization code already used (replay attack prevention)
- 400 Bad Request: redirect_uri mismatch (doesn't match authorize request)
- 400 Bad Request: client_id mismatch (doesn't match authorize request)
- 500 Internal Server Error: Store failure

---

### FR-3: User Info Retrieval

**Endpoint:** `GET /auth/userinfo`

**Description:** Retrieve authenticated user's profile information using a bearer token.

**Input:**

- Header: `Authorization: Bearer at_sess_abc123xyz`

**Output (Success - 200):**

```json
{
  "sub": "user_def456",
  "email": "user@example.com",
  "email_verified": false,
  "name": "User Example",
  "given_name": "User",
  "family_name": "Example"
}
```

**Business Logic:**

1. Extract bearer token from Authorization header
2. Validate format: "Bearer <token>"
3. Parse token to extract session*id (remove "at*" prefix)
4. Retrieve session from SessionStore
5. If session not found, return 401
6. Retrieve user from UserStore using session.UserID
7. If user not found, return 401
8. Return user profile in OIDC userinfo format

**Error Cases:**

- 401 Unauthorized: Missing or invalid Authorization header
- 401 Unauthorized: Token not found or expired
- 401 Unauthorized: User not found
- 500 Internal Server Error: Store failure

---

## 4. Technical Requirements

### TR-1: Data Models

**User Model** (Location: `internal/auth/models.go`)

```go
type User struct {
    ID        uuid.UUID    // Format: "user_<uuid>"
    Email     string    // Unique, valid email format
    FirstName string    // Extracted from email or provided
    LastName  string    // Extracted from email or provided
    Verified  bool      // Email verification status (default: false)
    CreatedAt time.Time // User creation timestamp
}
```

**Session Model** (Location: `internal/auth/models.go`)

```go
type Session struct {
    ID             uuid.UUID // Unique session identifier
    UserID         uuid.UUID // Foreign key to User.ID
    Code           string    // Authorization code (OAuth 2.0)
    CodeExpiresAt  time.Time // Authorization code expiry (10 minutes)
    CodeUsed       bool      // Whether code has been exchanged (prevent replay)
    ClientID       string    // OAuth client identifier
    RedirectURI    string    // Redirect URI from authorize request (for validation)
    RequestedScope []string  // Scopes like ["openid", "profile"]
    Status         string    // "pending_consent", "active", "expired"
    CreatedAt      time.Time // Session creation timestamp
    ExpiresAt      time.Time // Session expiry timestamp
}
```

### TR-2: Storage Interfaces

**UserStore** (Location: `internal/auth/store.go`)

```go
type UserStore interface {
    SaveUser(ctx context.Context, user *User) error
    FindUserByID(ctx context.Context, id string) (*User, error)
    FindUserByEmail(ctx context.Context, email string) (*User, error)
    DeleteUser(ctx context.Context, id string) error // For GDPR
}
```

**SessionStore** (Location: `internal/auth/store.go`)

```go
type SessionStore interface {
    Save(ctx context.Context, session *Session) error
    FindByID(ctx context.Context, id uuid.UUID) (*Session, error)
    FindByCode(ctx context.Context, code string) (*Session, error) // For token exchange
    DeleteSession(ctx context.Context, id uuid.UUID) error
    DeleteSessionsByUser(ctx context.Context, userID uuid.UUID) error // For GDPR
}
```

### TR-3: Service Layer

**AuthService** (Location: `internal/auth/service.go`)

```go
type AuthService struct {
    users    UserStore
    sessions SessionStore
}

func (s *AuthService) Authorize(ctx context.Context, req AuthorizationRequest) (*AuthorizationResult, error)
func (s *AuthService) Token(ctx context.Context, req TokenRequest) (*TokenResult, error)
func (s *AuthService) UserInfo(ctx context.Context, token string) (*User, error)
```

### TR-4: HTTP Handlers

**Handler Struct** (Location: `internal/transport/http/router.go`)

```go
type Handler struct {
    authService   *auth.AuthService
    // ... other services
}
```

**Handler Functions** (Location: `internal/transport/http/handlers_auth.go`)

```go
func (h *Handler) handleAuthorize(w http.ResponseWriter, r *http.Request)
func (h *Handler) handleToken(w http.ResponseWriter, r *http.Request)
func (h *Handler) handleUserInfo(w http.ResponseWriter, r *http.Request)
```

### TR-5: Dependencies

**Required:**

- `internal/platform/logger` - For structured logging
- `pkg/errors` - For typed error handling
- `internal/audit` - For logging authentication events

**Store Implementation:**

- Use `internal/auth/store_memory.go` (already implemented)
- Thread-safe with `sync.RWMutex`
- Returns typed errors from `pkg/errors`

---

## 5. API Specifications

### Endpoint Summary

| Endpoint          | Method | Auth Required | Purpose                     |
| ----------------- | ------ | ------------- | --------------------------- |
| `/auth/authorize` | POST   | No            | Start auth session          |
| `/auth/token`     | POST   | No            | Exchange session for tokens |
| `/auth/userinfo`  | GET    | Yes (Bearer)  | Get user profile            |

### Token Format

**Access Token:** `at_<session_id>`
**ID Token:** `idt_<session_id>`
**Token Type:** Bearer
**Lifetime:** 3600 seconds (1 hour)

**Note:** For MVP, tokens are simple opaque strings. Future enhancement: Use JWT with signatures.

### Error Response Format

All endpoints return errors in this format:

```json
{
  "error": "invalid_request",
  "error_description": "Missing required field: email",
  "status_code": 400
}
```

---

## 6. Security Requirements

### SR-1: Input Validation

- Validate all email addresses match regex: `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
- Validate redirect_uri is a valid URL with https:// scheme (http:// allowed for localhost)
- Sanitize all string inputs (trim whitespace, validate length)
- Reject requests with missing required fields

### SR-2: Token Security

- Tokens must be unguessable (include UUIDs)
- Tokens should expire after 1 hour
- Bearer tokens must be validated on every request

### SR-3: CSRF Protection

- When state parameter is provided in authorize request, echo it back in redirect_uri
- Clients should validate state matches their original value before using session_id
- State should be cryptographically random and unpredictable

### SR-4: Data Privacy

- Never log passwords (not applicable for email-only auth)
- Log only user IDs, not email addresses, in non-audit logs
- Use audit system for sensitive operations

---

## 7. Observability Requirements

### Logging

**Events to Log:**

- User created: `user_created` (audit)
- Session started: `session_created` (audit)
- Token issued: `token_issued` (audit)
- UserInfo accessed: `userinfo_accessed` (audit)
- Authentication failures: `auth_failed` (standard log)

**Log Format:**

```go
logger.Info("session created",
    "user_id", user.ID,
    "session_id", session.ID,
    "client_id", req.ClientID,
)
```

### Metrics

- Total users created (counter)
- Active sessions (gauge)
- Token requests per minute (rate)
- Auth failures per minute (rate)
- Latency per endpoint (histogram)

---

## 8. Testing Requirements

### Unit Tests

- [ ] Test user creation with valid email
- [ ] Test user retrieval by ID and email
- [ ] Test session creation and retrieval
- [ ] Test token generation format
- [ ] Test token validation and parsing
- [ ] Test redirect_uri building with session_id and state
- [ ] Test redirect_uri validation (https required, localhost exception)
- [ ] Test state parameter echo in response
- [ ] Test error cases (invalid email, invalid redirect_uri, not found, etc.)

### Integration Tests

- [ ] Test complete flow: authorize → token → userinfo
- [ ] Test concurrent user creation (race conditions)
- [ ] Test session expiry handling
- [ ] Test invalid bearer token rejection

### Manual Testing

```bash
# 1. Authorize - OAuth 2.0 Authorization Code Flow
curl -X POST http://localhost:8080/auth/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "client_id": "demo-client",
    "redirect_uri": "https://myapp.com/callback",
    "state": "random-csrf-token-123",
    "scopes": ["openid", "profile"]
  }'

# Expected Response:
# {
#   "code": "authz_550e8400-e29b-41d4-a716-446655440000",
#   "redirect_uri": "https://myapp.com/callback?code=authz_550e8400-e29b-41d4-a716-446655440000&state=random-csrf-token-123"
# }

# 2. Exchange Authorization Code for Tokens
curl -X POST http://localhost:8080/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "authz_550e8400-e29b-41d4-a716-446655440000",
    "redirect_uri": "https://myapp.com/callback",
    "client_id": "demo-client"
  }'

# Expected Response:
# {
#   "access_token": "at_550e8400-e29b-41d4-a716-446655440000",
#   "id_token": "idt_550e8400-e29b-41d4-a716-446655440000",
#   "token_type": "Bearer",
#   "expires_in": 3600
# }

# 3. Get UserInfo with Access Token
curl http://localhost:8080/auth/userinfo \
  -H "Authorization: Bearer at_550e8400-e29b-41d4-a716-446655440000"

# Expected Response:
# {
#   "sub": "550e8400-e29b-41d4-a716-446655440000",
#   "email": "alice@example.com",
#   "email_verified": false,
#   "name": "Alice Example",
#   "given_name": "Alice",
#   "family_name": "Example"
# }

# 4. Test Error Cases

# 4a. Try to reuse authorization code (should fail)
curl -X POST http://localhost:8080/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "authz_550e8400-e29b-41d4-a716-446655440000",
    "redirect_uri": "https://myapp.com/callback",
    "client_id": "demo-client"
  }'

# Expected: 401 Unauthorized (code already used)

# 4b. Try with wrong redirect_uri (should fail)
curl -X POST http://localhost:8080/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "authz_NEW_CODE",
    "redirect_uri": "https://evil.com/callback",
    "client_id": "demo-client"
  }'

# Expected: 400 Bad Request (redirect_uri mismatch)

# 4c. Try with unsupported grant_type (should fail)
curl -X POST http://localhost:8080/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "password",
    "username": "alice@example.com",
    "password": "secret"
  }'

# Expected: 400 Bad Request (unsupported grant_type)
```

---

## 9. Implementation Steps

### Phase 1: Service Layer (2-3 hours)

1. Update `AuthService` in `internal/auth/service.go`
2. Implement `Authorize()` method:
   - Find or create user by email
   - Create session
   - Return session ID and user ID
3. Implement `Token()` method:
   - Validate session
   - Generate tokens
   - Return token response
4. Implement `UserInfo()` method:
   - Parse bearer token
   - Retrieve session and user
   - Return user profile

### Phase 2: HTTP Handlers (1-2 hours)

1. Update `Handler` struct in `router.go` to include `AuthService`
2. Implement `handleAuthorize`:
   - Parse JSON request body
   - Call `authService.Authorize()`
   - Return JSON response or error
3. Implement `handleToken`:
   - Parse JSON request body
   - Call `authService.Token()`
   - Return JSON response or error
4. Implement `handleUserInfo`:
   - Extract bearer token from header
   - Call `authService.UserInfo()`
   - Return JSON response or error

### Phase 3: Dependency Injection (30 min)

1. Update `cmd/server/main.go`:
   - Initialize UserStore (already exists)
   - Initialize SessionStore (already exists)
   - Create AuthService with stores
   - Pass AuthService to HTTP Handler
2. Wire up in router

### Phase 4: Testing (1-2 hours)

1. Write unit tests for AuthService methods
2. Write integration test for complete flow
3. Manual testing with curl commands
4. Edge case testing (invalid inputs, not found, etc.)

---

## 10. Acceptance Criteria

- [ ] User can authenticate with email and receive session ID
- [ ] User can exchange session ID for access and ID tokens
- [ ] User can retrieve profile using bearer token
- [ ] Invalid bearer tokens return 401 Unauthorized
- [ ] Non-existent sessions return 404 Not Found
- [ ] All authentication events are logged to audit system
- [ ] Concurrent requests don't cause race conditions
- [ ] All endpoints return proper error responses
- [ ] Code passes `make test` and `make lint`
- [ ] Manual curl tests work as documented

---

## 11. Dependencies & Blockers

### Dependencies

- `internal/auth/store_memory.go` - ✅ Already implemented
- `pkg/errors` - ✅ Already implemented
- `internal/audit` - ✅ Already implemented
- `internal/platform/logger` - ✅ Already implemented

### Potential Blockers

- None identified

---

## 12. Future Enhancements (Out of Scope)

- Real JWT signing with RS256/ES256
- Refresh token support
- Session revocation endpoint
- Token introspection endpoint
- Password authentication
- Multi-factor authentication
- Rate limiting per user/IP
- OIDC discovery endpoint (/.well-known/openid-configuration)
- PKCE support for public clients

---

## 13. Open Questions

1. **Session Expiry:** Should sessions expire? If yes, after how long?

   - **Recommendation:** Yes, 24 hours for MVP

2. **User Auto-Creation:** Should we auto-create users on first auth?

   - **Recommendation:** Yes, for demo purposes. Simplifies onboarding.

3. **Token Revocation:** Do we need ability to revoke tokens?
   - **Recommendation:** Not for MVP. Add in Phase 2.

---

## 14. References

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- Tutorial: `docs/TUTORIAL.md` Section 1
- Architecture: `docs/architecture.md`
- Code Structure: `docs/structure.md`

---

## Revision History

| Version | Date       | Author       | Changes                                                                 |
| ------- | ---------- | ------------ | ----------------------------------------------------------------------- |
| 1.0     | 2025-12-03 | Product Team | Initial PRD                                                             |
| 1.1     | 2025-12-05 | Engineering  | Updated to OAuth 2.0 Authorization Code Flow (RFC 6749 compliant)      |
|         |            |              | - Changed authorize endpoint to return `code` instead of `session_id`  |
|         |            |              | - Updated token endpoint to use `grant_type` and `code`                |
|         |            |              | - Added code expiry, replay prevention, and redirect_uri validation    |
|         |            |              | - Updated Session model with Code, CodeExpiresAt, CodeUsed fields      |
|         |            |              | - Added FindByCode() to SessionStore interface                         |
